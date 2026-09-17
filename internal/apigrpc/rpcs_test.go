package apigrpc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"ztap/internal/audit"
	"ztap/internal/auth"
	"ztap/internal/cluster"
	"ztap/internal/enforcer"
	"ztap/internal/flow"
	"ztap/internal/ratelimit"

	apiv1 "ztap/proto/ztap/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type grpcEnv struct {
	conn    *grpc.ClientConn
	srv     *Server
	auth    *auth.AuthManager
	cleanup func()
	ctx     context.Context
	token   string
}

func newGRPCTestEnv(t *testing.T, cfg Config, withPolicy bool, withCluster bool) *grpcEnv {
	t.Helper()

	tmp := t.TempDir()
	t.Setenv("ZTAP_BOOTSTRAP_ADMIN_PASSWORD", "password123")
	am, err := auth.NewAuthManager(tmp + "/users.json")
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	al, err := audit.NewAuditLogger(tmp + "/audit.log")
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	var (
		election cluster.LeaderElection
		pm       cluster.PolicyManager
		pmSync   *cluster.InMemoryPolicySync
		ctx      context.Context
		cancel   context.CancelFunc
	)
	if withCluster || withPolicy {
		election = cluster.NewInMemoryElection(cluster.LeaderElectionConfig{
			NodeID:            "node-1",
			NodeAddress:       "127.0.0.1:0",
			HeartbeatInterval: 10 * time.Millisecond,
			ElectionTimeout:   100 * time.Millisecond,
			InitialLeadership: 10 * time.Millisecond,
		})
		ctx, cancel = context.WithCancel(t.Context())
		if err := election.Start(ctx); err != nil {
			cancel()
			t.Fatalf("Start election: %v", err)
		}
		waitForLeader(t, election)
		if withPolicy {
			pmSync = cluster.NewInMemoryPolicySync(election, "node-1")
			if err := pmSync.Start(ctx); err != nil {
				cancel()
				_ = election.Stop()
				t.Fatalf("Start policy sync: %v", err)
			}
			pm = pmSync
		}
	} else {
		ctx = t.Context()
	}

	if cfg.Listen == "" {
		cfg.Listen = "bufnet"
	}
	if cfg.AuthEnabled {
		cfg.AuthEnabled = true
	}

	flowFactory := func() flow.FlowReader {
		return flow.NewSimulatedReader(demoRawFlows(), 5*time.Millisecond)
	}

	srv, err := NewServer(ServerOptions{
		Config:            cfg,
		AuthManager:       am,
		AuditLogger:       al,
		PolicyManager:     pm,
		ClusterElection:   election,
		FlowReaderFactory: flowFactory,
	})
	if err != nil {
		if cancel != nil {
			cancel()
		}
		if election != nil {
			_ = election.Stop()
		}
		_ = am.Close()
		_ = al.Close()
		t.Fatalf("NewServer: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(
		grpc.ChainUnaryInterceptor(srv.unaryRateLimitInterceptor, srv.unaryAuthInterceptor),
		grpc.ChainStreamInterceptor(srv.streamRateLimitInterceptor, srv.streamAuthInterceptor),
	)
	srv.grpc = gs
	srv.registerServices()

	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		gs.Stop()
		if cancel != nil {
			cancel()
		}
		if election != nil {
			_ = election.Stop()
		}
		_ = am.Close()
		_ = al.Close()
		t.Fatalf("NewClient: %v", err)
	}

	token := ""
	if cfg.AuthEnabled {
		authClient := apiv1.NewAuthServiceClient(conn)
		resp, err := authClient.Login(t.Context(), &apiv1.LoginRequest{Username: "admin", Password: "password123"})
		if err != nil {
			_ = conn.Close()
			gs.Stop()
			if cancel != nil {
				cancel()
			}
			if election != nil {
				_ = election.Stop()
			}
			_ = am.Close()
			_ = al.Close()
			t.Fatalf("Login: %v", err)
		}
		token = resp.GetToken()
	}

	cleanup := func() {
		_ = conn.Close()
		gs.Stop()
		if pmSync != nil {
			_ = pmSync.Stop()
		}
		if election != nil {
			_ = election.Stop()
		}
		if cancel != nil {
			cancel()
		}
		_ = am.Close()
		_ = al.Close()
	}

	return &grpcEnv{conn: conn, srv: srv, auth: am, cleanup: cleanup, ctx: ctx, token: token}
}

func waitForLeader(t *testing.T, election cluster.LeaderElection) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if election.IsLeader() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("leader not elected")
}

func authCtx(token string) context.Context {
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
}

func TestGRPCStatusService(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	client := apiv1.NewStatusServiceClient(env.conn)
	resp, err := client.GetStatus(authCtx(env.token), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.GetOs() == "" || resp.GetArch() == "" {
		t.Fatalf("expected os/arch in status")
	}
}

func TestGRPCUsersLifecycle(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	client := apiv1.NewUsersServiceClient(env.conn)
	ctx := authCtx(env.token)

	if _, err := client.CreateUser(ctx, &apiv1.CreateUserRequest{Username: "bob", Password: "password123", Role: string(auth.RoleViewer)}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	listResp, err := client.ListUsers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(listResp.GetUsers()) == 0 {
		t.Fatalf("expected users")
	}

	if _, err := client.GetUser(ctx, &apiv1.GetUserRequest{Username: "bob"}); err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	if _, err := client.UpdateUser(ctx, &apiv1.UpdateUserRequest{Username: "bob", HasEnabled: true, Enabled: false}); err != nil {
		t.Fatalf("UpdateUser disable: %v", err)
	}
	if _, err := client.UpdateUser(ctx, &apiv1.UpdateUserRequest{Username: "bob", HasRole: true, Role: string(auth.RoleOperator)}); err != nil {
		t.Fatalf("UpdateUser role: %v", err)
	}

	if _, err := client.SetUserPassword(ctx, &apiv1.SetUserPasswordRequest{Username: "bob", HasOldPassword: true, OldPassword: "password123", NewPassword: "password456"}); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}

	if _, err := client.DeleteUser(ctx, &apiv1.DeleteUserRequest{Username: "bob"}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
}

func TestGRPCUsersPermissionDenied(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	if err := env.auth.CreateUser("viewer", "pw", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok := loginGRPCToken(t, env.conn, "viewer", "pw")

	ctx := authCtx(tok)
	usersClient := apiv1.NewUsersServiceClient(env.conn)
	_, err := usersClient.ListUsers(ctx, &emptypb.Empty{})
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestGRPCPolicyRevisionsAndRollback(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, true, true)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewPolicyServiceClient(env.conn)

	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: web\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"
	if _, err := client.PutPolicy(ctx, &apiv1.PutPolicyRequest{Tenant: "default", Name: "web", PolicyYaml: policyYAML}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if _, err := client.PutPolicy(ctx, &apiv1.PutPolicyRequest{Tenant: "default", Name: "web", PolicyYaml: policyYAML, Reason: "update"}); err != nil {
		t.Fatalf("PutPolicy update: %v", err)
	}

	revList, err := client.ListPolicyRevisions(ctx, &apiv1.ListPolicyRevisionsRequest{Tenant: "default", Name: "web"})
	if err != nil {
		t.Fatalf("ListPolicyRevisions: %v", err)
	}
	if len(revList.GetRevisions()) < 2 {
		t.Fatalf("expected revisions")
	}

	rev, err := client.GetPolicyRevision(ctx, &apiv1.GetPolicyRevisionRequest{Tenant: "default", Name: "web", Version: 1})
	if err != nil {
		t.Fatalf("GetPolicyRevision: %v", err)
	}
	if rev.GetRevision().GetVersion() != 1 {
		t.Fatalf("expected version 1")
	}

	if _, err := client.RollbackPolicy(ctx, &apiv1.RollbackPolicyRequest{Tenant: "default", Name: "web", ToVersion: 1, Reason: "rollback"}); err != nil {
		t.Fatalf("RollbackPolicy: %v", err)
	}
}

func TestGRPCPolicyExpectedVersionMismatch(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, true, true)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewPolicyServiceClient(env.conn)

	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: db\nspec:\n  podSelector:\n    matchLabels:\n      app: db\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 5432\n"
	if _, err := client.PutPolicy(ctx, &apiv1.PutPolicyRequest{Tenant: "default", Name: "db", PolicyYaml: policyYAML}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}

	_, err := client.PutPolicy(ctx, &apiv1.PutPolicyRequest{Tenant: "default", Name: "db", PolicyYaml: policyYAML, HasExpectedVersion: true, ExpectedVersion: 100})
	st, _ := status.FromError(err)
	if st.Code() != codes.Aborted {
		t.Fatalf("expected Aborted, got %v", st.Code())
	}
}

func TestGRPCClusterRPCs(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, true)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewClusterServiceClient(env.conn)

	if _, err := client.RegisterNode(ctx, &apiv1.RegisterNodeRequest{Node: &apiv1.ClusterNode{Id: "node-2", Address: "127.0.0.1:9000"}}); err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
	if _, err := client.ListNodes(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if _, err := client.GetClusterStatus(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if _, err := client.DeregisterNode(ctx, &apiv1.DeregisterNodeRequest{NodeId: "node-2"}); err != nil {
		t.Fatalf("DeregisterNode: %v", err)
	}
}

func TestGRPCUnconfiguredServices(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)

	policyClient := apiv1.NewPolicyServiceClient(env.conn)
	_, err := policyClient.ListPolicies(ctx, &apiv1.ListPoliciesRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.Unimplemented {
		t.Fatalf("expected unimplemented for policy manager, got %v", st.Code())
	}

	clusterClient := apiv1.NewClusterServiceClient(env.conn)
	_, err = clusterClient.GetClusterStatus(ctx, &emptypb.Empty{})
	if st, _ := status.FromError(err); st.Code() != codes.Unimplemented {
		t.Fatalf("expected unimplemented for cluster election, got %v", st.Code())
	}
}

func TestGRPCAuthErrors(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	client := apiv1.NewAuthServiceClient(env.conn)

	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Basic token"))
	_, err := client.WhoAmI(ctx, &emptypb.Empty{})
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated for invalid scheme")
	}

	_, err = client.WhoAmI(t.Context(), &emptypb.Empty{})
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated for missing metadata")
	}
}

func TestGRPCEnforcementStartAndStop(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	oldPF := enforceWithPF
	defer func() {
		enforceWithPF = oldPF
	}()

	enforceWithPF = func(_ enforcer.EnforcementOptions) error { return nil }

	ctx := authCtx(env.token)
	client := apiv1.NewEnforcementServiceClient(env.conn)
	if enforcer.IsLinux() {
		_, err := client.Start(ctx, &apiv1.EnforcementStartRequest{PolicyYaml: "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: retired\nspec:\n  podSelector: {}\n"})
		if st, _ := status.FromError(err); st.Code() != codes.Unimplemented {
			t.Fatalf("expected Linux direct enforcement to be retired, got %v", err)
		}
		_, err = client.Stop(ctx, &emptypb.Empty{})
		if st, _ := status.FromError(err); st.Code() != codes.Unimplemented {
			t.Fatalf("expected Linux direct stop to be retired, got %v", err)
		}
		return
	}

	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: web\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"

	startResp, err := client.Start(ctx, &apiv1.EnforcementStartRequest{PolicyYaml: policyYAML})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !startResp.GetEnforced() {
		t.Fatalf("expected enforced response")
	}

	_, err = client.Stop(ctx, &emptypb.Empty{})
	if err == nil {
		t.Fatalf("expected error on non-linux stop")
	}
	if st, _ := status.FromError(err); st.Code() != codes.Unimplemented {
		t.Fatalf("expected unimplemented, got %v", st.Code())
	}
}

func TestGRPCEnforcementStartErrors(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewEnforcementServiceClient(env.conn)

	_, err := client.Start(ctx, &apiv1.EnforcementStartRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}

	_, err = client.Start(ctx, &apiv1.EnforcementStartRequest{PolicyYaml: "invalid: ["})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument for bad yaml, got %v", st.Code())
	}
}

func TestGRPCPolicyGetNotFound(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, true, true)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewPolicyServiceClient(env.conn)

	_, err := client.GetPolicy(ctx, &apiv1.GetPolicyRequest{Tenant: "default", Name: "missing"})
	if st, _ := status.FromError(err); st.Code() != codes.NotFound {
		t.Fatalf("expected not found, got %v", st.Code())
	}
}

func TestGRPCPolicyPutMissingName(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, true, true)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewPolicyServiceClient(env.conn)

	_, err := client.PutPolicy(ctx, &apiv1.PutPolicyRequest{PolicyYaml: "test"})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}
}

func TestGRPCPolicyDeleteNotFound(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, true, true)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewPolicyServiceClient(env.conn)

	_, err := client.DeletePolicy(ctx, &apiv1.DeletePolicyRequest{Tenant: "default", Name: "missing"})
	if st, _ := status.FromError(err); st.Code() != codes.NotFound {
		t.Fatalf("expected not found, got %v", st.Code())
	}
}

func TestGRPCClusterRegisterErrors(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, true)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewClusterServiceClient(env.conn)

	_, err := client.RegisterNode(ctx, &apiv1.RegisterNodeRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}

	_, err = client.DeregisterNode(ctx, &apiv1.DeregisterNodeRequest{NodeId: ""})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}
}

func TestGRPCUsersValidationErrors(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	ctx := authCtx(env.token)
	client := apiv1.NewUsersServiceClient(env.conn)

	_, err := client.CreateUser(ctx, &apiv1.CreateUserRequest{Username: "", Password: "pw"})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}

	_, err = client.UpdateUser(ctx, &apiv1.UpdateUserRequest{Username: "bob"})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}

	_, err = client.SetUserPassword(ctx, &apiv1.SetUserPasswordRequest{Username: ""})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}

	_, err = client.DeleteUser(ctx, &apiv1.DeleteUserRequest{Username: ""})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}
}

func TestGRPCAuthLoginErrors(t *testing.T) {
	env := newGRPCTestEnv(t, Config{Listen: "bufnet", AuthEnabled: true}, false, false)
	t.Cleanup(env.cleanup)

	client := apiv1.NewAuthServiceClient(env.conn)
	_, err := client.Login(t.Context(), &apiv1.LoginRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", st.Code())
	}
	_, err = client.Login(t.Context(), &apiv1.LoginRequest{Username: "admin", Password: "wrong"})
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", st.Code())
	}
}

func TestGRPCBearerTokenParsing(t *testing.T) {
	if tok, ok := ratelimitBearer("Bearer test"); !ok || tok != "test" {
		t.Fatalf("expected bearer token")
	}
	if _, ok := ratelimitBearer("Basic test"); ok {
		t.Fatalf("expected non-bearer to fail")
	}
}

func TestGRPCPeerIP(t *testing.T) {
	ctx := peerContext(&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 123})
	if got := peerIP(ctx); got != "10.0.0.1" {
		t.Fatalf("expected peer ip, got %s", got)
	}

	ctx = peerContext(&net.IPAddr{IP: net.ParseIP("10.0.0.2")})
	if got := peerIP(ctx); got != "10.0.0.2" {
		t.Fatalf("expected peer ip, got %s", got)
	}

	if got := peerIP(t.Context()); got != "0.0.0.0" {
		t.Fatalf("expected default ip, got %s", got)
	}
}

func peerContext(addr net.Addr) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
}

func TestGRPCDecisionForGRPCDisabled(t *testing.T) {
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "bufnet", AuthEnabled: false}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	dec := srv.decisionForGRPC(t.Context())
	if !dec.Allowed || dec.Bucket == "" {
		t.Fatalf("expected allowed decision when disabled")
	}
}

func TestGRPCRateLimitStatusDetails(t *testing.T) {
	err := rateLimitStatus(ratelimit.Decision{Allowed: false, RetryAfter: 2 * time.Second})
	st, _ := status.FromError(err)
	if st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected resource exhausted")
	}
	if len(st.Details()) == 0 {
		t.Fatalf("expected retry info details")
	}
}

func TestGRPCSessionFromContextMissing(t *testing.T) {
	if sess, ok := sessionFromContext(t.Context()); ok || sess != nil {
		t.Fatalf("expected no session")
	}
}

func TestGRPCUserStatusError(t *testing.T) {
	if st, _ := status.FromError(userStatusError(auth.ErrUserNotFound)); st.Code() != codes.NotFound {
		t.Fatalf("expected not found")
	}
	if st, _ := status.FromError(userStatusError(auth.ErrLastAdmin)); st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected failed precondition")
	}
	if st, _ := status.FromError(userStatusError(auth.ErrUserExists)); st.Code() != codes.AlreadyExists {
		t.Fatalf("expected already exists")
	}
	if st, _ := status.FromError(userStatusError(errors.New("boom"))); st.Code() != codes.InvalidArgument {
		t.Fatalf("expected invalid argument")
	}
}
