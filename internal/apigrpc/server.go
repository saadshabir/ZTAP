package apigrpc

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"ztap/internal/alert"
	"ztap/internal/apiutil"
	"ztap/internal/audit"
	"ztap/internal/auth"
	"ztap/internal/cluster"
	"ztap/internal/enforcer"
	"ztap/internal/flow"
	"ztap/internal/health"
	"ztap/internal/logging"
	"ztap/internal/policy"
	"ztap/internal/ratelimit"
	apiv1 "ztap/proto/ztap/api/v1"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	errdetails "google.golang.org/genproto/googleapis/rpc/errdetails"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

var (
	enforceWithPF = enforcer.EnforceWithPF
)

type Config struct {
	Listen      string
	AuthEnabled bool
	TLS         TLSConfig
	RateLimit   RateLimitConfig
}

type RateLimitConfig struct {
	Enabled bool

	Unauthenticated RateLimitBucketConfig
	PerIP           RateLimitBucketConfig
	PerToken        RateLimitBucketConfig

	ExemptMethods []string
}

type RateLimitBucketConfig struct {
	RPS   float64
	Burst int
}

type TLSConfig struct {
	Enabled      bool
	CertFile     string
	KeyFile      string
	ClientAuth   bool
	ClientCAFile string
}

type ServerOptions struct {
	Config Config

	AuthManager *auth.AuthManager
	AuditLogger *audit.AuditLogger
	Alerts      *alert.Manager

	FlowReaderFactory func() flow.FlowReader
	PolicyManager     cluster.PolicyManager
	ClusterElection   cluster.LeaderElection

	// Discovery is an optional service discovery backend used for resolving
	// selector targets (podSelector with optional namespaceSelector) when
	// enforcement is started via the API.
	Discovery policy.ServiceDiscovery

	// ResolveLabelsInterval controls re-resolution of podSelector targets over
	// time when discovery is configured. If 0, refresh is disabled.
	ResolveLabelsInterval time.Duration
}

type Server struct {
	cfg       Config
	grpc      *grpc.Server
	auth      *auth.AuthManager
	audit     *audit.AuditLogger
	readiness *health.Checker
	startTime time.Time
	alerts    *alert.Manager

	flowReader      func() flow.FlowReader
	policyManager   cluster.PolicyManager
	clusterElection cluster.LeaderElection

	rateLimiter *ratelimit.Store
	rlAllowed   *prometheus.CounterVec
	rlLimited   *prometheus.CounterVec

	discovery             policy.ServiceDiscovery
	resolveLabelsInterval time.Duration

	discoveryMu      sync.Mutex
	discoveryStarted bool

	enforcementMu   sync.Mutex
	refreshCancelFn context.CancelFunc
	runCtx          context.Context
}

func NewServer(opts ServerOptions) (*Server, error) {
	if strings.TrimSpace(opts.Config.Listen) == "" {
		opts.Config.Listen = "127.0.0.1:9092"
	}
	if opts.AuthManager == nil {
		am, err := apiutil.DefaultAuthManager()
		if err != nil {
			return nil, err
		}
		opts.AuthManager = am
	}
	if opts.AuditLogger == nil {
		al, err := apiutil.DefaultAuditLogger()
		if err != nil {
			return nil, err
		}
		opts.AuditLogger = al
	}
	if opts.FlowReaderFactory == nil {
		opts.FlowReaderFactory = createFlowReader
	}

	s := &Server{
		cfg:                   opts.Config,
		auth:                  opts.AuthManager,
		audit:                 opts.AuditLogger,
		readiness:             &health.Checker{AuthEnabled: opts.Config.AuthEnabled, Auth: opts.AuthManager, Audit: opts.AuditLogger},
		startTime:             time.Now(),
		alerts:                opts.Alerts,
		flowReader:            opts.FlowReaderFactory,
		policyManager:         opts.PolicyManager,
		clusterElection:       opts.ClusterElection,
		discovery:             opts.Discovery,
		resolveLabelsInterval: opts.ResolveLabelsInterval,
		runCtx:                context.Background(),
	}

	s.initRateLimiting()

	grpcOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(s.unaryRateLimitInterceptor, s.unaryAuthInterceptor),
		grpc.ChainStreamInterceptor(s.streamRateLimitInterceptor, s.streamAuthInterceptor),
	}

	if s.cfg.TLS.Enabled {
		if s.cfg.TLS.CertFile == "" || s.cfg.TLS.KeyFile == "" {
			return nil, errors.New("gRPC TLS is enabled but certificate or key file is missing")
		}
		// Build tls.Config to support optional client cert verification
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server TLS keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		if s.cfg.TLS.ClientAuth {
			if s.cfg.TLS.ClientCAFile == "" {
				return nil, errors.New("gRPC mTLS is enabled but client CA file is missing")
			}
			pem, err := os.ReadFile(s.cfg.TLS.ClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read client CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("no certificates found in gRPC client CA file")
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		creds := credentials.NewTLS(tlsCfg)
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}

	s.grpc = grpc.NewServer(grpcOpts...)

	s.registerServices()
	return s, nil
}

func (s *Server) ListenAddr() string {
	return s.cfg.Listen
}

func (s *Server) Serve(ctx context.Context) error {
	s.runCtx = ctx
	defer s.stopEnforcementRefresh()
	defer func() {
		if s.discovery != nil {
			_ = s.discovery.Stop()
		}
	}()

	defer func() {
		if s.rateLimiter != nil {
			s.rateLimiter.Close()
		}
	}()

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	errCh := make(chan error, 1)

	if s.alerts != nil {
		s.alerts.Start(ctx)
		defer s.alerts.Close()
	}
	go func() {
		errCh <- s.grpc.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		s.grpc.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *Server) stopEnforcementRefreshLocked() {
	if s.refreshCancelFn == nil {
		return
	}
	s.refreshCancelFn()
	s.refreshCancelFn = nil
}

func (s *Server) stopEnforcementRefresh() {
	s.enforcementMu.Lock()
	defer s.enforcementMu.Unlock()
	s.stopEnforcementRefreshLocked()
}

func (s *Server) ensureDiscoveryStarted() error {
	if s.discovery == nil {
		return nil
	}

	s.discoveryMu.Lock()
	defer s.discoveryMu.Unlock()
	if s.discoveryStarted {
		return nil
	}

	starter, ok := s.discovery.(interface{ Start(context.Context) error })
	if ok {
		base := s.runCtx
		if base == nil {
			base = context.Background()
		}
		if err := starter.Start(base); err != nil {
			return err
		}
	}

	s.discoveryStarted = true
	return nil
}

func policiesNeedTargetResolution(policies []policy.NetworkPolicy) bool {
	return policy.NeedsTargetResolution(policies)
}

type ctxKey int

const sessionKey ctxKey = 1

func sessionFromContext(ctx context.Context) (*auth.Session, bool) {
	sess, ok := ctx.Value(sessionKey).(*auth.Session)
	return sess, ok
}

func auditActor(ctx context.Context) string {
	if sess, ok := sessionFromContext(ctx); ok {
		return sess.Username
	}
	return "system"
}

func (s *Server) emitAlert(a alert.Alert) {
	if s.alerts == nil {
		return
	}
	_ = s.alerts.Emit(a)
}

func (s *Server) initRateLimiting() {
	rcfg := ratelimit.DefaultConfig()
	rcfg.Enabled = s.cfg.RateLimit.Enabled

	unauth := s.cfg.RateLimit.Unauthenticated
	if unauth.RPS == 0 {
		unauth.RPS = rcfg.Unauthenticated.RPS
	}
	if unauth.Burst == 0 {
		unauth.Burst = rcfg.Unauthenticated.Burst
	}
	perIP := s.cfg.RateLimit.PerIP
	if perIP.RPS == 0 {
		perIP.RPS = rcfg.PerIP.RPS
	}
	if perIP.Burst == 0 {
		perIP.Burst = rcfg.PerIP.Burst
	}
	perTok := s.cfg.RateLimit.PerToken
	if perTok.RPS == 0 {
		perTok.RPS = rcfg.PerToken.RPS
	}
	if perTok.Burst == 0 {
		perTok.Burst = rcfg.PerToken.Burst
	}

	rcfg.Unauthenticated = ratelimit.BucketConfig{RPS: unauth.RPS, Burst: unauth.Burst}
	rcfg.PerIP = ratelimit.BucketConfig{RPS: perIP.RPS, Burst: perIP.Burst}
	rcfg.PerToken = ratelimit.BucketConfig{RPS: perTok.RPS, Burst: perTok.Burst}

	rcfg.ExemptPaths = nil
	s.rateLimiter = ratelimit.NewStore(rcfg)

	if !rcfg.Enabled {
		return
	}

	s.rlAllowed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ztap_api_rate_limit_allowed_total",
		Help: "Total number of API requests allowed by rate limiter",
	}, []string{"surface", "bucket"})
	s.rlLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ztap_api_rate_limit_limited_total",
		Help: "Total number of API requests rejected by rate limiter",
	}, []string{"surface", "bucket"})

	_ = prometheus.Register(s.rlAllowed)
	_ = prometheus.Register(s.rlLimited)
}

func (s *Server) isExemptMethod(fullMethod string) bool {
	switch fullMethod {
	case "/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/List", "/grpc.health.v1.Health/Watch":
		return true
	}
	for _, m := range s.cfg.RateLimit.ExemptMethods {
		if m == fullMethod {
			return true
		}
		if before, ok := strings.CutSuffix(m, "*"); ok {
			prefix := before
			if strings.HasPrefix(fullMethod, prefix) {
				return true
			}
		}
	}
	return false
}

func (s *Server) unaryRateLimitInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !s.cfg.RateLimit.Enabled {
		return handler(ctx, req)
	}
	if s.isExemptMethod(info.FullMethod) {
		return handler(ctx, req)
	}

	dec := s.decisionForGRPC(ctx)
	if dec.Allowed {
		if s.rlAllowed != nil {
			s.rlAllowed.WithLabelValues("grpc", dec.Bucket).Inc()
		}
		return handler(ctx, req)
	}

	if s.rlLimited != nil {
		s.rlLimited.WithLabelValues("grpc", dec.Bucket).Inc()
	}
	return nil, rateLimitStatus(dec)
}

func (s *Server) streamRateLimitInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !s.cfg.RateLimit.Enabled {
		return handler(srv, ss)
	}
	if s.isExemptMethod(info.FullMethod) {
		return handler(srv, ss)
	}

	dec := s.decisionForGRPC(ss.Context())
	if dec.Allowed {
		if s.rlAllowed != nil {
			s.rlAllowed.WithLabelValues("grpc", dec.Bucket).Inc()
		}
		return handler(srv, ss)
	}

	if s.rlLimited != nil {
		s.rlLimited.WithLabelValues("grpc", dec.Bucket).Inc()
	}
	return rateLimitStatus(dec)
}

func rateLimitStatus(dec ratelimit.Decision) error {
	st := status.New(codes.ResourceExhausted, "rate limited")
	if dec.RetryAfter > 0 {
		d := max(dec.RetryAfter, 0)
		stWith, err := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(d)})
		if err == nil {
			return stWith.Err()
		}
	}
	return st.Err()
}

func (s *Server) decisionForGRPC(ctx context.Context) ratelimit.Decision {
	if s.rateLimiter == nil {
		return ratelimit.Decision{Allowed: true, Bucket: "disabled"}
	}

	// Token bucket first (if auth header provided), then IP bucket.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vals := md.Get("authorization")
		if len(vals) > 0 {
			if tok, ok := ratelimitBearer(vals[0]); ok {
				if s.cfg.AuthEnabled {
					if _, err := s.auth.ValidateSession(tok); err != nil {
						// Invalid token -> unauthenticated bucket.
						ip := peerIP(ctx)
						d := s.rateLimiter.DecisionForKey(ratelimit.KeyUnauthenticated, "ip:"+ip)
						d.Bucket = "unauthenticated"
						return d
					}
				}

				d := s.rateLimiter.DecisionForKey(ratelimit.KeyToken, "token:"+ratelimit.HashToken(tok))
				d.Bucket = "per_token"
				if !d.Allowed {
					return d
				}

				ip := peerIP(ctx)
				d2 := s.rateLimiter.DecisionForKey(ratelimit.KeyIP, "ip:"+ip)
				d2.Bucket = "per_ip"
				return d2
			}
		}
	}

	// No token => use unauthenticated bucket.
	ip := peerIP(ctx)
	d := s.rateLimiter.DecisionForKey(ratelimit.KeyUnauthenticated, "ip:"+ip)
	d.Bucket = "unauthenticated"
	return d
}

func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "0.0.0.0"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err == nil {
		if parsed := net.ParseIP(host); parsed != nil {
			return parsed.String()
		}
	}
	if parsed := net.ParseIP(p.Addr.String()); parsed != nil {
		return parsed.String()
	}
	return "0.0.0.0"
}

func ratelimitBearer(h string) (string, bool) {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	if strings.ToLower(strings.TrimSpace(parts[0])) != "bearer" {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func validateFullMethod(fullMethod string) error {
	if !strings.HasPrefix(fullMethod, "/") {
		return status.Error(codes.Unimplemented, "malformed grpc method path")
	}
	parts := strings.Split(fullMethod, "/")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return status.Error(codes.Unimplemented, "malformed grpc method path")
	}
	return nil
}

func (s *Server) unaryAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := validateFullMethod(info.FullMethod); err != nil {
		return nil, err
	}

	perm, requiresAuth, known := permissionForMethod(info.FullMethod)
	if !known {
		return nil, status.Error(codes.Unimplemented, "unknown grpc method")
	}
	if !requiresAuth || !s.cfg.AuthEnabled {
		return handler(ctx, req)
	}

	tok, err := bearerTokenFromMetadata(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.auth.HasPermission(tok, perm); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	sess, err := s.auth.ValidateSession(tok)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	ctx = context.WithValue(ctx, sessionKey, sess)
	return handler(ctx, req)
}

func (s *Server) streamAuthInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := validateFullMethod(info.FullMethod); err != nil {
		return err
	}

	perm, requiresAuth, known := permissionForMethod(info.FullMethod)
	if !known {
		return status.Error(codes.Unimplemented, "unknown grpc method")
	}
	if !requiresAuth || !s.cfg.AuthEnabled {
		return handler(srv, ss)
	}

	tok, err := bearerTokenFromMetadata(ss.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.auth.HasPermission(tok, perm); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	sess, err := s.auth.ValidateSession(tok)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	wrapped := &serverStreamWithContext{ServerStream: ss, ctx: context.WithValue(ss.Context(), sessionKey, sess)}
	return handler(srv, wrapped)
}

type serverStreamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStreamWithContext) Context() context.Context { return s.ctx }

func bearerTokenFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing request metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", errors.New("missing authorization metadata")
	}

	h := vals[0]
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid authorization metadata")
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(parts[0])), []byte("bearer")) != 1 {
		return "", errors.New("invalid authorization scheme")
	}
	okTok := strings.TrimSpace(parts[1])
	if okTok == "" {
		return "", errors.New("empty bearer token")
	}
	return okTok, nil
}

func permissionForMethod(fullMethod string) (auth.Permission, bool, bool) {
	switch fullMethod {
	case apiv1.AuthService_Login_FullMethodName:
		return "", false, true
	case "/grpc.health.v1.Health/Check":
		return "", false, true
	case "/grpc.health.v1.Health/Watch":
		return "", false, true
	case apiv1.AuthService_WhoAmI_FullMethodName:
		return auth.PermViewStatus, true, true
	case apiv1.StatusService_GetStatus_FullMethodName:
		return auth.PermViewStatus, true, true
	case apiv1.EnforcementService_GetStatus_FullMethodName:
		return auth.PermViewStatus, true, true
	case apiv1.EnforcementService_Start_FullMethodName:
		return auth.PermEnforce, true, true
	case apiv1.EnforcementService_Stop_FullMethodName:
		return auth.PermEnforce, true, true
	case apiv1.FlowsService_Stream_FullMethodName:
		return auth.PermViewStatus, true, true
	case apiv1.PolicyService_ListPolicies_FullMethodName:
		return auth.PermViewPolicies, true, true
	case apiv1.PolicyService_GetPolicy_FullMethodName:
		return auth.PermViewPolicies, true, true
	case apiv1.PolicyService_PutPolicy_FullMethodName:
		return auth.PermManagePolicies, true, true
	case apiv1.PolicyService_DeletePolicy_FullMethodName:
		return auth.PermManagePolicies, true, true
	case apiv1.PolicyService_ListPolicyRevisions_FullMethodName:
		return auth.PermViewPolicies, true, true
	case apiv1.PolicyService_GetPolicyRevision_FullMethodName:
		return auth.PermViewPolicies, true, true
	case apiv1.PolicyService_RollbackPolicy_FullMethodName:
		return auth.PermManagePolicies, true, true
	case apiv1.UsersService_ListUsers_FullMethodName:
		return auth.PermManageUsers, true, true
	case apiv1.UsersService_GetUser_FullMethodName:
		return auth.PermManageUsers, true, true
	case apiv1.UsersService_CreateUser_FullMethodName:
		return auth.PermManageUsers, true, true
	case apiv1.UsersService_UpdateUser_FullMethodName:
		return auth.PermManageUsers, true, true
	case apiv1.UsersService_SetUserPassword_FullMethodName:
		return auth.PermManageUsers, true, true
	case apiv1.UsersService_DeleteUser_FullMethodName:
		return auth.PermManageUsers, true, true
	case apiv1.ClusterService_GetClusterStatus_FullMethodName:
		return auth.PermManageCluster, true, true
	case apiv1.ClusterService_ListNodes_FullMethodName:
		return auth.PermManageCluster, true, true
	case apiv1.ClusterService_RegisterNode_FullMethodName:
		return auth.PermManageCluster, true, true
	case apiv1.ClusterService_DeregisterNode_FullMethodName:
		return auth.PermManageCluster, true, true
	default:
		return "", false, false
	}
}

func (s *Server) registerServices() {
	apiv1.RegisterAuthServiceServer(s.grpc, &authService{srv: s})
	apiv1.RegisterStatusServiceServer(s.grpc, &statusService{srv: s})
	apiv1.RegisterEnforcementServiceServer(s.grpc, &enforcementService{srv: s})
	apiv1.RegisterFlowsServiceServer(s.grpc, &flowsService{srv: s})
	apiv1.RegisterPolicyServiceServer(s.grpc, &policyService{srv: s})
	apiv1.RegisterUsersServiceServer(s.grpc, &usersService{srv: s})
	apiv1.RegisterClusterServiceServer(s.grpc, &clusterService{srv: s})

	grpc_health_v1.RegisterHealthServer(s.grpc, &healthService{srv: s})
}

type healthService struct{ srv *Server }

func (h *healthService) Check(ctx context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	res := h.srv.readiness.Check(ctx)
	st := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if res.Ready {
		st = grpc_health_v1.HealthCheckResponse_SERVING
	}
	return &grpc_health_v1.HealthCheckResponse{Status: st}, nil
}

func (h *healthService) Watch(_ *grpc_health_v1.HealthCheckRequest, srv grpc_health_v1.Health_WatchServer) error {
	res := h.srv.readiness.Check(srv.Context())
	st := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if res.Ready {
		st = grpc_health_v1.HealthCheckResponse_SERVING
	}
	return srv.Send(&grpc_health_v1.HealthCheckResponse{Status: st})
}

// List implements the newer health check List RPC which streams the
// service health statuses. For our simple readiness checker we send a
// single status and return.
// List returns a snapshot of all known service health statuses. The
// grpc health proto defines a HealthListRequest/HealthListResponse pair.
// For our simple readiness checker we return a single entry (the overall
// server status) in the Statuses map.
func (h *healthService) List(ctx context.Context, _ *grpc_health_v1.HealthListRequest) (*grpc_health_v1.HealthListResponse, error) {
	res := h.srv.readiness.Check(ctx)
	st := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if res.Ready {
		st = grpc_health_v1.HealthCheckResponse_SERVING
	}
	return &grpc_health_v1.HealthListResponse{
		Statuses: map[string]*grpc_health_v1.HealthCheckResponse{"": {Status: st}},
	}, nil
}

type authService struct {
	apiv1.UnimplementedAuthServiceServer
	srv *Server
}

type statusService struct {
	apiv1.UnimplementedStatusServiceServer
	srv *Server
}

type enforcementService struct {
	apiv1.UnimplementedEnforcementServiceServer
	srv *Server
}

type flowsService struct {
	apiv1.UnimplementedFlowsServiceServer
	srv *Server
}

type policyService struct {
	apiv1.UnimplementedPolicyServiceServer
	srv *Server
}

type usersService struct {
	apiv1.UnimplementedUsersServiceServer
	srv *Server
}

type clusterService struct {
	apiv1.UnimplementedClusterServiceServer
	srv *Server
}

func (a *authService) Login(ctx context.Context, req *apiv1.LoginRequest) (*apiv1.LoginResponse, error) {
	username := strings.TrimSpace(req.GetUsername())
	password := strings.TrimSpace(req.GetPassword())
	if username == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}

	sess, err := a.srv.auth.Authenticate(ctx, username, password)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	return &apiv1.LoginResponse{
		Token:     sess.Token,
		Username:  sess.Username,
		Role:      string(sess.Role),
		ExpiresAt: timestamppb.New(sess.ExpiresAt.UTC()),
	}, nil
}

func (a *authService) WhoAmI(ctx context.Context, _ *emptypb.Empty) (*apiv1.WhoAmIResponse, error) {
	sess, ok := sessionFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "missing session")
	}
	return &apiv1.WhoAmIResponse{
		Username:  sess.Username,
		Role:      string(sess.Role),
		ExpiresAt: timestamppb.New(sess.ExpiresAt.UTC()),
	}, nil
}

func (st *statusService) GetStatus(ctx context.Context, _ *emptypb.Empty) (*apiv1.StatusResponse, error) {
	hostname, _ := os.Hostname()
	return &apiv1.StatusResponse{
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
		Pid:      int64(os.Getpid()),
		Uptime:   time.Since(st.srv.startTime).Truncate(time.Second).String(),
	}, nil
}

func (e *enforcementService) GetStatus(ctx context.Context, _ *emptypb.Empty) (*apiv1.EnforcementStatusResponse, error) {
	return &apiv1.EnforcementStatusResponse{
		Platform:          runtime.GOOS,
		EbpfActive:        enforcer.IsEBPFEnforcementActive(),
		FlowEventsPinPath: enforcer.DefaultFlowEventsPinPath,
	}, nil
}

func (e *enforcementService) Start(ctx context.Context, req *apiv1.EnforcementStartRequest) (*apiv1.EnforcementStartResponse, error) {
	if enforcer.IsLinux() {
		return nil, status.Error(codes.Unimplemented, enforcer.ErrLegacyLinuxEnforcementRetired.Error())
	}
	policyYAML := strings.TrimSpace(req.GetPolicyYaml())
	policyName := strings.TrimSpace(req.GetPolicyName())

	if policyYAML == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_yaml is required")
	}
	if policyName == "" {
		policyName = "api"
	}
	policyTenant := cluster.DefaultTenant
	policyShortName := policyName
	policyKey := cluster.PolicyKey{Tenant: policyTenant, Name: policyShortName}.String()
	if parsed, err := cluster.ParsePolicyKey(policyName); err == nil {
		policyTenant = parsed.Tenant
		policyShortName = parsed.Name
		policyKey = parsed.String()
	}

	basePolicies, err := policy.LoadFromBytes([]byte(policyYAML))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse policy yaml: %v", err)
	}
	if len(basePolicies) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no policies found")
	}

	needsResolution := policiesNeedTargetResolution(basePolicies)

	e.srv.enforcementMu.Lock()
	defer e.srv.enforcementMu.Unlock()

	policies := basePolicies
	if needsResolution {
		if e.srv.discovery == nil {
			return nil, status.Error(codes.InvalidArgument, "policy contains podSelector targets but no discovery backend is configured")
		}
		if err := e.srv.ensureDiscoveryStarted(); err != nil {
			logging.Errorf("failed to start discovery backend: %v", err)
			return nil, status.Error(codes.Internal, "failed to start discovery backend")
		}
		enforcer.WarnNoMatchPolicyTargets(e.srv.discovery, enforcer.SelectorRefreshOptions{Scope: policyTenant}, basePolicies)
		resolver := policy.NewPolicyResolver(e.srv.discovery)
		resolved, err := resolver.ResolvePodSelectorsToIPBlocksScoped(policyTenant, basePolicies)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to resolve pod selectors: %v", err)
		}
		policies = resolved
	}
	normalized, err := policy.NormalizePolicies(policies)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to normalize ipBlocks: %v", err)
	}
	policies = normalized

	named := make([]policy.NamedPolicy, 0, len(basePolicies))
	for _, p := range basePolicies {
		if err := p.Validate(); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		named = append(named, policy.NamedPolicy{Tenant: policyTenant, PolicyName: policyShortName, Policy: p})
	}
	for i, np := range named {
		if err := policy.CheckConflicts(named[:i], np); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "policy conflict: %v", err)
		}
	}

	platform := runtime.GOOS
	srvCtx := e.srv.runCtx
	if srvCtx == nil {
		srvCtx = context.Background()
	}
	if err := enforceWithPF(enforcer.EnforcementOptions{Policies: policies, Context: srvCtx}); err != nil {
		logging.Errorf("failed to enforce via pf: %v", err)
		return nil, status.Error(codes.Internal, "failed to enforce policy")
	}
	e.srv.stopEnforcementRefreshLocked()
	_ = e.srv.audit.Log(audit.EventPolicyEnforced, "system", policyKey, "enforce", map[string]any{"platform": runtime.GOOS, "count": len(policies)})
	e.srv.emitAlert(alert.Alert{Source: "api-grpc", Severity: alert.SeverityInfo, Title: "policy enforced", Message: fmt.Sprintf("%s enforced on %s", policyKey, platform), DedupKey: fmt.Sprintf("%s:%s:success", policyKey, platform), Details: map[string]any{"platform": platform, "count": len(policies)}})
	return &apiv1.EnforcementStartResponse{Enforced: true, Platform: platform}, nil
}

func (e *enforcementService) Stop(ctx context.Context, _ *emptypb.Empty) (*apiv1.EnforcementStopResponse, error) {
	if enforcer.IsLinux() {
		return nil, status.Error(codes.Unimplemented, "direct Linux enforcement is retired; stop the ztap agent process instead")
	}
	e.srv.enforcementMu.Lock()
	defer e.srv.enforcementMu.Unlock()
	e.srv.stopEnforcementRefreshLocked()

	return nil, status.Error(codes.Unimplemented, "stop is only supported for WFP on windows or pf on macOS")
}

func (f *flowsService) Stream(_ *emptypb.Empty, stream apiv1.FlowsService_StreamServer) error {
	ctx := stream.Context()

	reader := f.srv.flowReader()
	monitor := flow.NewMonitor(reader)
	if err := monitor.Start(ctx); err != nil {
		logging.Errorf("failed to start flow monitor: %v", err)
		return status.Error(codes.Internal, "failed to start flow monitor")
	}
	defer func() { _ = monitor.Stop() }()

	eventCh := monitor.Subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-eventCh:
			if !ok {
				return nil
			}
			msg := flowEventToPB(ev)
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func (p *policyService) ListPolicies(ctx context.Context, req *apiv1.ListPoliciesRequest) (*apiv1.ListPoliciesResponse, error) {
	if p.srv.policyManager == nil {
		return nil, status.Error(codes.Unimplemented, "policy manager not configured")
	}
	tenant := strings.TrimSpace(req.GetTenant())
	items := p.srv.policyManager.ListPolicies()
	resp := &apiv1.ListPoliciesResponse{Policies: make([]*apiv1.PolicySummary, 0, len(items))}
	for _, item := range items {
		if tenant != "" && item.Tenant != tenant {
			continue
		}
		resp.Policies = append(resp.Policies, &apiv1.PolicySummary{
			Tenant:    item.Tenant,
			Name:      item.Name,
			Version:   item.Version,
			Source:    item.Source,
			UpdatedAt: timestamppb.New(item.Timestamp.UTC()),
		})
	}
	return resp, nil
}

func (p *policyService) GetPolicy(ctx context.Context, req *apiv1.GetPolicyRequest) (*apiv1.GetPolicyResponse, error) {
	if p.srv.policyManager == nil {
		return nil, status.Error(codes.Unimplemented, "policy manager not configured")
	}
	key := strings.TrimSpace(req.GetTenant())
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if key == "" {
		key = cluster.DefaultTenant
	}
	policyKey := key + "/" + name
	state, err := p.srv.policyManager.GetPolicy(policyKey)
	if err != nil {
		logging.Errorf("failed to get policy %s: %v", policyKey, err)
		return nil, status.Error(codes.Internal, "failed to retrieve policy")
	}
	if state == nil {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	return &apiv1.GetPolicyResponse{Policy: &apiv1.Policy{
		Tenant:     state.Tenant,
		Name:       state.Name,
		Version:    state.Version,
		Source:     state.Source,
		UpdatedAt:  timestamppb.New(state.Timestamp.UTC()),
		PolicyYaml: string(state.YAML),
	}}, nil
}

func (p *policyService) PutPolicy(ctx context.Context, req *apiv1.PutPolicyRequest) (*apiv1.PutPolicyResponse, error) {
	if p.srv.policyManager == nil {
		return nil, status.Error(codes.Unimplemented, "policy manager not configured")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	policyYAML := strings.TrimSpace(req.GetPolicyYaml())
	if policyYAML == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_yaml is required")
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		tenant = cluster.DefaultTenant
	}
	policyKey := tenant + "/" + name
	if req.GetHasExpectedVersion() {
		expected := req.GetExpectedVersion()
		if expected < 0 {
			return nil, status.Error(codes.InvalidArgument, "expected_version must be >= 0")
		}
		current, err := p.srv.policyManager.GetPolicyVersion(policyKey)
		if err != nil {
			logging.Errorf("failed to get policy version for %s: %v", policyKey, err)
			return nil, status.Error(codes.Internal, "failed to retrieve policy version")
		}
		if current != expected {
			return nil, status.Error(codes.Aborted, fmt.Sprintf("expected version %d, got %d", expected, current))
		}
	}
	rev, err := p.srv.policyManager.UpsertPolicy(ctx, policyKey, []byte(policyYAML), strings.TrimSpace(req.GetReason()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if p.srv.audit != nil {
		event := audit.EventPolicyUpdated
		if rev.Version == 1 {
			event = audit.EventPolicyCreated
		}
		_ = p.srv.audit.Log(event, auditActor(ctx), policyKey, "upsert", map[string]any{"version": rev.Version})
	}
	return &apiv1.PutPolicyResponse{Version: rev.Version}, nil
}

func (p *policyService) DeletePolicy(ctx context.Context, req *apiv1.DeletePolicyRequest) (*apiv1.DeletePolicyResponse, error) {
	if p.srv.policyManager == nil {
		return nil, status.Error(codes.Unimplemented, "policy manager not configured")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		tenant = cluster.DefaultTenant
	}
	policyKey := tenant + "/" + name
	rev, err := p.srv.policyManager.DeletePolicy(ctx, policyKey, strings.TrimSpace(req.GetReason()))
	if err != nil {
		if errors.Is(err, cluster.ErrPolicyNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if p.srv.audit != nil {
		_ = p.srv.audit.Log(audit.EventPolicyDeleted, auditActor(ctx), policyKey, "delete", map[string]any{"version": rev.Version, "reason": strings.TrimSpace(req.GetReason())})
	}
	return &apiv1.DeletePolicyResponse{Version: rev.Version, Deleted: true}, nil
}

func (p *policyService) ListPolicyRevisions(ctx context.Context, req *apiv1.ListPolicyRevisionsRequest) (*apiv1.ListPolicyRevisionsResponse, error) {
	if p.srv.policyManager == nil {
		return nil, status.Error(codes.Unimplemented, "policy manager not configured")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		tenant = cluster.DefaultTenant
	}
	policyKey := tenant + "/" + name
	limit := int(req.GetLimit())
	revs, err := p.srv.policyManager.ListPolicyRevisions(policyKey, limit)
	if err != nil {
		logging.Errorf("failed to list policy revisions for %s: %v", policyKey, err)
		return nil, status.Error(codes.Internal, "failed to list policy revisions")
	}
	resp := &apiv1.ListPolicyRevisionsResponse{Revisions: make([]*apiv1.PolicyRevision, 0, len(revs))}
	includeYAML := req.GetIncludeYaml()
	for _, rev := range revs {
		info := &apiv1.PolicyRevision{
			Tenant:                 rev.Tenant,
			Name:                   rev.PolicyName,
			Version:                rev.Version,
			Source:                 rev.Source,
			CreatedAt:              timestamppb.New(rev.Timestamp.UTC()),
			Reason:                 rev.Reason,
			Deleted:                rev.Deleted,
			RollbackFromVersion:    0,
			HasRollbackFromVersion: false,
		}
		if rev.RollbackFromVersion != nil {
			info.RollbackFromVersion = *rev.RollbackFromVersion
			info.HasRollbackFromVersion = true
		}
		if includeYAML {
			info.PolicyYaml = string(rev.YAML)
		}
		resp.Revisions = append(resp.Revisions, info)
	}
	return resp, nil
}

func (p *policyService) GetPolicyRevision(ctx context.Context, req *apiv1.GetPolicyRevisionRequest) (*apiv1.GetPolicyRevisionResponse, error) {
	if p.srv.policyManager == nil {
		return nil, status.Error(codes.Unimplemented, "policy manager not configured")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetVersion() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "version must be positive")
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		tenant = cluster.DefaultTenant
	}
	policyKey := tenant + "/" + name
	rev, err := p.srv.policyManager.GetPolicyRevision(policyKey, req.GetVersion())
	if err != nil {
		logging.Errorf("failed to get policy revision for %s v%d: %v", policyKey, req.GetVersion(), err)
		return nil, status.Error(codes.Internal, "failed to retrieve policy revision")
	}
	if rev == nil {
		return nil, status.Error(codes.NotFound, "revision not found")
	}
	info := &apiv1.PolicyRevision{
		Tenant:                 rev.Tenant,
		Name:                   rev.PolicyName,
		Version:                rev.Version,
		Source:                 rev.Source,
		CreatedAt:              timestamppb.New(rev.Timestamp.UTC()),
		Reason:                 rev.Reason,
		Deleted:                rev.Deleted,
		RollbackFromVersion:    0,
		HasRollbackFromVersion: false,
		PolicyYaml:             string(rev.YAML),
	}
	if rev.RollbackFromVersion != nil {
		info.RollbackFromVersion = *rev.RollbackFromVersion
		info.HasRollbackFromVersion = true
	}
	return &apiv1.GetPolicyRevisionResponse{Revision: info}, nil
}

func (p *policyService) RollbackPolicy(ctx context.Context, req *apiv1.RollbackPolicyRequest) (*apiv1.RollbackPolicyResponse, error) {
	if p.srv.policyManager == nil {
		return nil, status.Error(codes.Unimplemented, "policy manager not configured")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetToVersion() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "to_version must be positive")
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		tenant = cluster.DefaultTenant
	}
	policyKey := tenant + "/" + name
	rev, err := p.srv.policyManager.RollbackPolicy(ctx, policyKey, req.GetToVersion(), strings.TrimSpace(req.GetReason()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if p.srv.audit != nil {
		_ = p.srv.audit.Log(audit.EventPolicyUpdated, auditActor(ctx), policyKey, "rollback", map[string]any{"version": rev.Version, "rollback_from": req.GetToVersion()})
	}
	return &apiv1.RollbackPolicyResponse{Version: rev.Version}, nil
}

func (u *usersService) ListUsers(ctx context.Context, _ *emptypb.Empty) (*apiv1.ListUsersResponse, error) {
	if u.srv.auth == nil {
		return nil, status.Error(codes.Internal, "auth manager not configured")
	}
	users := u.srv.auth.ListUsers()
	resp := &apiv1.ListUsersResponse{Users: make([]*apiv1.User, 0, len(users))}
	for _, user := range users {
		info := &apiv1.User{
			Username:  user.Username,
			Role:      string(user.Role),
			Enabled:   user.Enabled,
			CreatedAt: timestamppb.New(user.CreatedAt.UTC()),
		}
		if !user.LastLogin.IsZero() {
			info.LastLogin = timestamppb.New(user.LastLogin.UTC())
		}
		resp.Users = append(resp.Users, info)
	}
	return resp, nil
}

func (u *usersService) GetUser(ctx context.Context, req *apiv1.GetUserRequest) (*apiv1.User, error) {
	if u.srv.auth == nil {
		return nil, status.Error(codes.Internal, "auth manager not configured")
	}
	username := strings.TrimSpace(req.GetUsername())
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	user, err := u.srv.auth.GetUser(username)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		logging.Errorf("failed to get user %s: %v", username, err)
		return nil, status.Error(codes.Internal, "failed to retrieve user")
	}
	info := &apiv1.User{
		Username:  user.Username,
		Role:      string(user.Role),
		Enabled:   user.Enabled,
		CreatedAt: timestamppb.New(user.CreatedAt.UTC()),
	}
	if !user.LastLogin.IsZero() {
		info.LastLogin = timestamppb.New(user.LastLogin.UTC())
	}
	return info, nil
}

func (u *usersService) CreateUser(ctx context.Context, req *apiv1.CreateUserRequest) (*apiv1.CreateUserResponse, error) {
	if u.srv.auth == nil {
		return nil, status.Error(codes.Internal, "auth manager not configured")
	}
	username := strings.TrimSpace(req.GetUsername())
	password := req.GetPassword()
	role := strings.TrimSpace(req.GetRole())
	if username == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}
	if len(password) < 8 {
		return nil, status.Error(codes.InvalidArgument, "password must be at least 8 characters")
	}
	if role == "" {
		role = string(auth.RoleOperator)
	}
	if err := u.srv.auth.CreateUser(username, password, auth.Role(role)); err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if u.srv.audit != nil {
		_ = u.srv.audit.Log(audit.EventUserCreated, auditActor(ctx), username, "create", map[string]any{"role": role})
	}
	user, _ := u.srv.auth.GetUser(username)
	info := &apiv1.User{
		Username:  user.Username,
		Role:      string(user.Role),
		Enabled:   user.Enabled,
		CreatedAt: timestamppb.New(user.CreatedAt.UTC()),
	}
	return &apiv1.CreateUserResponse{User: info}, nil
}

func (u *usersService) UpdateUser(ctx context.Context, req *apiv1.UpdateUserRequest) (*apiv1.UpdateUserResponse, error) {
	if u.srv.auth == nil {
		return nil, status.Error(codes.Internal, "auth manager not configured")
	}
	username := strings.TrimSpace(req.GetUsername())
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if !req.GetHasRole() && !req.GetHasEnabled() {
		return nil, status.Error(codes.InvalidArgument, "role or enabled must be provided")
	}
	if req.GetHasRole() {
		if err := u.srv.auth.SetUserRole(username, auth.Role(strings.TrimSpace(req.GetRole()))); err != nil {
			return nil, userStatusError(err)
		}
	}
	if req.GetHasEnabled() {
		if req.GetEnabled() {
			if err := u.srv.auth.EnableUser(username); err != nil {
				return nil, userStatusError(err)
			}
			if u.srv.audit != nil {
				_ = u.srv.audit.Log(audit.EventUserEnabled, auditActor(ctx), username, "enable", nil)
			}
		} else {
			if err := u.srv.auth.DisableUser(username); err != nil {
				return nil, userStatusError(err)
			}
			if u.srv.audit != nil {
				_ = u.srv.audit.Log(audit.EventUserDisabled, auditActor(ctx), username, "disable", nil)
			}
		}
	}
	user, err := u.srv.auth.GetUser(username)
	if err != nil {
		return nil, userStatusError(err)
	}
	info := &apiv1.User{
		Username:  user.Username,
		Role:      string(user.Role),
		Enabled:   user.Enabled,
		CreatedAt: timestamppb.New(user.CreatedAt.UTC()),
	}
	if !user.LastLogin.IsZero() {
		info.LastLogin = timestamppb.New(user.LastLogin.UTC())
	}
	return &apiv1.UpdateUserResponse{User: info}, nil
}

func (u *usersService) SetUserPassword(ctx context.Context, req *apiv1.SetUserPasswordRequest) (*apiv1.SetUserPasswordResponse, error) {
	if u.srv.auth == nil {
		return nil, status.Error(codes.Internal, "auth manager not configured")
	}
	username := strings.TrimSpace(req.GetUsername())
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	newPassword := req.GetNewPassword()
	if newPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}
	if len(newPassword) < 8 {
		return nil, status.Error(codes.InvalidArgument, "password must be at least 8 characters")
	}
	if req.GetHasOldPassword() {
		if err := u.srv.auth.ChangePassword(username, req.GetOldPassword(), newPassword); err != nil {
			return nil, userStatusError(err)
		}
	} else {
		if err := u.srv.auth.SetPassword(username, newPassword); err != nil {
			return nil, userStatusError(err)
		}
	}
	return &apiv1.SetUserPasswordResponse{Updated: true}, nil
}

func (u *usersService) DeleteUser(ctx context.Context, req *apiv1.DeleteUserRequest) (*apiv1.DeleteUserResponse, error) {
	if u.srv.auth == nil {
		return nil, status.Error(codes.Internal, "auth manager not configured")
	}
	username := strings.TrimSpace(req.GetUsername())
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := u.srv.auth.DeleteUser(username); err != nil {
		return nil, userStatusError(err)
	}
	if u.srv.audit != nil {
		_ = u.srv.audit.Log(audit.EventUserDisabled, auditActor(ctx), username, "delete", nil)
	}
	return &apiv1.DeleteUserResponse{Deleted: true}, nil
}

func userStatusError(err error) error {
	if err == nil {
		return status.Error(codes.Internal, "unknown error")
	}
	if errors.Is(err, auth.ErrUserNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	if errors.Is(err, auth.ErrLastAdmin) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if errors.Is(err, auth.ErrUserExists) {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	return status.Error(codes.InvalidArgument, err.Error())
}

func (c *clusterService) GetClusterStatus(ctx context.Context, _ *emptypb.Empty) (*apiv1.GetClusterStatusResponse, error) {
	if c.srv.clusterElection == nil {
		return nil, status.Error(codes.Unimplemented, "cluster election not configured")
	}
	nodes := c.srv.clusterElection.GetNodes()
	leader := c.srv.clusterElection.GetLeader()
	resp := &apiv1.ClusterStatus{
		IsLeader:   c.srv.clusterElection.IsLeader(),
		Nodes:      make([]*apiv1.ClusterNode, 0, len(nodes)),
		UpdatedAt:  timestamppb.New(time.Now().UTC()),
		TotalNodes: safeNodesCount(nodes),
	}
	if leader != nil {
		resp.Leader = toClusterNode(leader)
	}
	for _, node := range nodes {
		resp.Nodes = append(resp.Nodes, toClusterNode(node))
	}
	return &apiv1.GetClusterStatusResponse{Status: resp}, nil
}

func (c *clusterService) ListNodes(ctx context.Context, _ *emptypb.Empty) (*apiv1.ListNodesResponse, error) {
	if c.srv.clusterElection == nil {
		return nil, status.Error(codes.Unimplemented, "cluster election not configured")
	}
	nodes := c.srv.clusterElection.GetNodes()
	resp := &apiv1.ListNodesResponse{Nodes: make([]*apiv1.ClusterNode, 0, len(nodes))}
	for _, node := range nodes {
		resp.Nodes = append(resp.Nodes, toClusterNode(node))
	}
	return resp, nil
}

func (c *clusterService) RegisterNode(ctx context.Context, req *apiv1.RegisterNodeRequest) (*apiv1.RegisterNodeResponse, error) {
	if c.srv.clusterElection == nil {
		return nil, status.Error(codes.Unimplemented, "cluster election not configured")
	}
	node := req.GetNode()
	if node == nil {
		return nil, status.Error(codes.InvalidArgument, "node is required")
	}
	if strings.TrimSpace(node.GetId()) == "" || strings.TrimSpace(node.GetAddress()) == "" {
		return nil, status.Error(codes.InvalidArgument, "node id and address are required")
	}
	joinedAt := time.Now()
	if node.GetJoinedAt() != nil {
		joinedAt = node.GetJoinedAt().AsTime()
	}
	lastSeen := time.Now()
	if node.GetLastSeen() != nil {
		lastSeen = node.GetLastSeen().AsTime()
	}
	cn := &cluster.Node{
		ID:       node.GetId(),
		Address:  node.GetAddress(),
		Role:     node.GetRole(),
		State:    cluster.NodeState(node.GetState()),
		JoinedAt: joinedAt,
		LastSeen: lastSeen,
		Metadata: node.GetMetadata(),
	}
	if cn.State == "" {
		cn.State = cluster.StateHealthy
	}
	if cn.Metadata == nil {
		cn.Metadata = map[string]string{}
	}
	if err := c.srv.clusterElection.RegisterNode(cn); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &apiv1.RegisterNodeResponse{Node: toClusterNode(cn)}, nil
}

func (c *clusterService) DeregisterNode(ctx context.Context, req *apiv1.DeregisterNodeRequest) (*apiv1.DeregisterNodeResponse, error) {
	if c.srv.clusterElection == nil {
		return nil, status.Error(codes.Unimplemented, "cluster election not configured")
	}
	nodeID := strings.TrimSpace(req.GetNodeId())
	if nodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}
	if err := c.srv.clusterElection.DeregisterNode(nodeID); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &apiv1.DeregisterNodeResponse{Deleted: true}, nil
}

func toClusterNode(node *cluster.Node) *apiv1.ClusterNode {
	if node == nil {
		return nil
	}
	resp := &apiv1.ClusterNode{
		Id:       node.ID,
		Address:  node.Address,
		Role:     node.Role,
		State:    string(node.State),
		JoinedAt: timestamppb.New(node.JoinedAt.UTC()),
		LastSeen: timestamppb.New(node.LastSeen.UTC()),
		Metadata: node.Metadata,
	}
	return resp
}

func safeNodesCount(nodes []*cluster.Node) int32 {
	return int32(min(len(nodes), int(math.MaxInt32)))
}

func flowEventToPB(ev flow.FlowEvent) *apiv1.FlowEvent {
	return &apiv1.FlowEvent{
		Timestamp:  timestamppb.New(ev.Timestamp.UTC()),
		SourceIp:   ev.SourceIP.String(),
		DestIp:     ev.DestIP.String(),
		SourcePort: uint32(ev.SourcePort),
		DestPort:   uint32(ev.DestPort),
		Protocol:   ev.Protocol,
		Direction:  ev.Direction,
		Action:     ev.Action,
	}
}
