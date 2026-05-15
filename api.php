<?php
// ============================================================
//  SISTEMA DE CONTRACHEQUES — IECPN
//  api.php  —  Backend PHP + MySQL
// ============================================================

// ── CONFIGURAÇÃO DO BANCO ──────────────────────────────────
define('DB_HOST', 'localhost');
define('DB_NAME', 'iecpn_contracheques');
define('DB_USER', 'root');          // ← altere para seu usuário
define('DB_PASS', '');              // ← altere para sua senha
define('DB_PORT', '3306');

// ── CONFIGURAÇÕES GERAIS ───────────────────────────────────
define('SESSION_LIFETIME', 3600 * 8); // 8 horas
define('MAX_PDF_MB', 10);             // tamanho máximo do PDF em MB
define('APP_VERSION', '2.0.0');

// ── HEADERS ───────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');

// CORS — ajuste para o domínio real em produção
$allowed_origin = $_SERVER['HTTP_ORIGIN'] ?? '';
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ── SESSION ───────────────────────────────────────────────
ini_set('session.cookie_httponly', 1);
ini_set('session.use_strict_mode', 1);
session_set_cookie_params(['lifetime' => SESSION_LIFETIME, 'samesite' => 'Strict']);
session_start();

// ── BANCO DE DADOS ─────────────────────────────────────────
function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    try {
        $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', DB_HOST, DB_PORT, DB_NAME);
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    } catch (PDOException $e) {
        resp(500, 'Falha na conexão com o banco de dados.');
    }
    return $pdo;
}

// ── HELPERS ────────────────────────────────────────────────
function resp(int $code, $data, string $message = ''): never {
    http_response_code($code);
    echo json_encode([
        'ok'      => $code >= 200 && $code < 300,
        'code'    => $code,
        'message' => $message,
        'data'    => $data,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

function ok($data = null, string $msg = ''): never    { resp(200, $data, $msg); }
function err(int $c, string $msg): never              { resp($c, null, $msg); }

function body(): array {
    $raw = file_get_contents('php://input');
    return json_decode($raw, true) ?? [];
}

function auth(array $roles = []): array {
    if (empty($_SESSION['user_id'])) err(401, 'Não autenticado.');
    if (!empty($roles) && !in_array($_SESSION['user_role'], $roles, true))
        err(403, 'Acesso não permitido para o perfil ' . $_SESSION['user_role'] . '.');
    return [
        'id'   => (int)$_SESSION['user_id'],
        'role' => $_SESSION['user_role'],
        'name' => $_SESSION['user_name'],
    ];
}

function logAction(int $userId = null, string $acao = '', string $desc = ''): void {
    try {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? null;
        db()->prepare(
            'INSERT INTO log_acoes (usuario_id, acao, descricao, ip) VALUES (?,?,?,?)'
        )->execute([$userId, $acao, $desc, $ip]);
    } catch (Throwable) {}
}

function sanitizeStr(string $v): string { return trim(strip_tags($v)); }
function onlyDigits(string $v): string  { return preg_replace('/\D/', '', $v); }

// ── ROTEADOR ──────────────────────────────────────────────
$method = $_SERVER['REQUEST_METHOD'];
$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Remove base path se necessário (ex: /sistema/api.php/login → /login)
$base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
$path = '/' . ltrim(str_replace($base, '', $uri), '/');
// remove o próprio nome do script
$path = preg_replace('#^/api\.php#', '', $path);
if ($path === '') $path = '/';

$route = $method . ' ' . rtrim($path, '/');

// ── ROTAS ─────────────────────────────────────────────────
match(true) {

    // ── AUTH ────────────────────────────────────────────
    $route === 'POST /auth/login'  => routeLogin(),
    $route === 'POST /auth/logout' => routeLogout(),
    $route === 'GET /auth/me'      => routeMe(),

    // ── USUÁRIOS ────────────────────────────────────────
    $route === 'GET /usuarios'           => routeListarUsuarios(),
    $route === 'POST /usuarios'          => routeCriarUsuario(),
    str_starts_with($path, '/usuarios/') && $method === 'PUT'    => routeEditarUsuario(),
    str_starts_with($path, '/usuarios/') && $method === 'DELETE' => routeExcluirUsuario(),

    // ── CONTRACHEQUES ───────────────────────────────────
    $route === 'GET /contracheques'              => routeListarCheques(),
    $route === 'POST /contracheques'             => routeEnviarCheque(),
    str_starts_with($path, '/contracheques/') && str_ends_with($path, '/ciencia') && $method === 'PUT'
                                                 => routeMarcarCiencia(),
    str_starts_with($path, '/contracheques/') && $method === 'DELETE'
                                                 => routeExcluirCheque(),

    // ── STATS ────────────────────────────────────────────
    $route === 'GET /stats' => routeStats(),

    // ── LOG ──────────────────────────────────────────────
    $route === 'GET /logs' => routeLogs(),

    // ── HEALTH ───────────────────────────────────────────
    $route === 'GET /'       => ok(['version' => APP_VERSION, 'status' => 'ok']),
    $route === 'GET /health' => ok(['version' => APP_VERSION, 'status' => 'ok']),

    default => err(404, 'Rota não encontrada: ' . $route),
};

// ════════════════════════════════════════════════════════════
//  IMPLEMENTAÇÕES
// ════════════════════════════════════════════════════════════

// ── LOGIN ──────────────────────────────────────────────────
function routeLogin(): never {
    $b    = body();
    $user = sanitizeStr($b['username'] ?? '');
    $pass = $b['password'] ?? '';
    $mode = $b['mode'] ?? 'colaborador'; // 'privilegiado' | 'colaborador'

    if (!$user || !$pass) err(400, 'Usuário e senha são obrigatórios.');

    if ($mode === 'privilegiado') {
        $stmt = db()->prepare(
            "SELECT id, username, password_hash, role, nome_completo
             FROM usuarios WHERE username = ? AND role IN ('superadmin','admin','rh') AND ativo = 1"
        );
        $stmt->execute([$user]);
    } else {
        $cpf  = onlyDigits($user);
        $stmt = db()->prepare(
            "SELECT id, username, password_hash, role, nome_completo, matricula, cpf
             FROM usuarios WHERE cpf = ? AND role = 'colaborador' AND ativo = 1"
        );
        $stmt->execute([$cpf]);
    }

    $row = $stmt->fetch();
    if (!$row || !password_verify($pass, $row['password_hash']))
        err(401, 'Credenciais inválidas.');

    // regenera session por segurança
    session_regenerate_id(true);
    $_SESSION['user_id']   = $row['id'];
    $_SESSION['user_role'] = $row['role'];
    $_SESSION['user_name'] = $row['nome_completo'] ?: $row['username'];

    logAction($row['id'], 'login', 'Login bem-sucedido via modo ' . $mode);

    unset($row['password_hash']);
    ok($row, 'Login realizado com sucesso.');
}

// ── LOGOUT ─────────────────────────────────────────────────
function routeLogout(): never {
    $uid = $_SESSION['user_id'] ?? null;
    session_destroy();
    if ($uid) logAction((int)$uid, 'logout', '');
    ok(null, 'Sessão encerrada.');
}

// ── ME ─────────────────────────────────────────────────────
function routeMe(): never {
    $u = auth();
    $stmt = db()->prepare(
        "SELECT id, username, nome_completo, role, matricula, cpf, criado_em FROM usuarios WHERE id = ?"
    );
    $stmt->execute([$u['id']]);
    $row = $stmt->fetch();
    if (!$row) err(404, 'Usuário não encontrado.');
    ok($row);
}

// ── LISTAR USUÁRIOS ────────────────────────────────────────
function routeListarUsuarios(): never {
    $me = auth(['superadmin','admin','rh']);

    $role   = $_GET['role'] ?? null;
    $busca  = $_GET['q']    ?? null;

    $where = ['1=1'];
    $params = [];

    if ($role) {
        $where[] = 'role = ?';
        $params[] = $role;
    }
    if ($busca) {
        $b = '%' . $busca . '%';
        $where[] = '(nome_completo LIKE ? OR username LIKE ? OR matricula LIKE ? OR cpf LIKE ?)';
        array_push($params, $b, $b, $b, '%' . onlyDigits($busca) . '%');
    }

    $sql  = 'SELECT id, username, nome_completo, role, matricula, cpf, ativo, criado_em
             FROM usuarios WHERE ' . implode(' AND ', $where) . ' ORDER BY nome_completo';
    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    ok($stmt->fetchAll());
}

// ── CRIAR USUÁRIO ──────────────────────────────────────────
function routeCriarUsuario(): never {
    $b    = body();
    $role = sanitizeStr($b['role'] ?? 'colaborador');

    // permissão: apenas superadmin cria privilegiados; colaborador se auto-cadastra (sem auth)
    if (in_array($role, ['superadmin','admin','rh'], true)) {
        auth(['superadmin']);
    }

    $nome      = sanitizeStr($b['nome_completo'] ?? $b['username'] ?? '');
    $username  = sanitizeStr($b['username'] ?? '');
    $pass      = $b['password'] ?? '';
    $matricula = sanitizeStr($b['matricula'] ?? '');
    $cpf       = onlyDigits($b['cpf'] ?? '');

    if (!$nome || !$pass) err(400, 'Nome e senha são obrigatórios.');
    if (strlen($pass) < 6) err(400, 'Senha deve ter no mínimo 6 caracteres.');

    if ($role === 'colaborador') {
        if (!$matricula) err(400, 'Matrícula é obrigatória para colaborador.');
        if (strlen($cpf) !== 11) err(400, 'CPF inválido.');
        // unicidade
        $dup = db()->prepare("SELECT id FROM usuarios WHERE cpf = ? OR matricula = ?");
        $dup->execute([$cpf, $matricula]);
        if ($dup->fetch()) err(409, 'CPF ou matrícula já cadastrados.');
    } else {
        if (!$username) err(400, 'Username é obrigatório para perfis privilegiados.');
        $dup = db()->prepare("SELECT id FROM usuarios WHERE username = ?");
        $dup->execute([$username]);
        if ($dup->fetch()) err(409, 'Username já existe.');
    }

    $hash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 12]);

    $stmt = db()->prepare(
        "INSERT INTO usuarios (username, password_hash, role, nome_completo, matricula, cpf)
         VALUES (?,?,?,?,?,?)"
    );
    $stmt->execute([
        $username ?: $nome,
        $hash,
        $role,
        $nome,
        $matricula ?: null,
        $cpf ?: null,
    ]);
    $newId = (int)db()->lastInsertId();

    $actor = $_SESSION['user_id'] ?? null;
    logAction($actor, 'criar_usuario', "Criou usuário id=$newId role=$role nome=$nome");

    ok(['id' => $newId], 'Usuário criado com sucesso.');
}

// ── EDITAR USUÁRIO ─────────────────────────────────────────
function routeEditarUsuario(): never {
    $me  = auth(['superadmin','admin']);
    $uid = (int)(explode('/', trim($path ?? $GLOBALS['path'], '/'))[1] ?? 0);

    // busca usuário alvo
    $stmt = db()->prepare("SELECT * FROM usuarios WHERE id = ?");
    $stmt->execute([$uid]);
    $target = $stmt->fetch();
    if (!$target) err(404, 'Usuário não encontrado.');

    // só superadmin pode editar superadmin
    if ($target['role'] === 'superadmin' && $me['role'] !== 'superadmin')
        err(403, 'Somente superadmin pode editar outro superadmin.');

    $b = body();
    $sets   = [];
    $params = [];

    if (isset($b['nome_completo'])) {
        $sets[] = 'nome_completo = ?';
        $params[] = sanitizeStr($b['nome_completo']);
    }
    if (isset($b['matricula'])) {
        $sets[] = 'matricula = ?';
        $params[] = sanitizeStr($b['matricula']);
    }
    if (isset($b['cpf'])) {
        $sets[] = 'cpf = ?';
        $params[] = onlyDigits($b['cpf']);
    }
    if (isset($b['role']) && $me['role'] === 'superadmin') {
        $sets[] = 'role = ?';
        $params[] = sanitizeStr($b['role']);
    }
    if (!empty($b['password'])) {
        if (strlen($b['password']) < 6) err(400, 'Senha mínima de 6 caracteres.');
        $sets[] = 'password_hash = ?';
        $params[] = password_hash($b['password'], PASSWORD_BCRYPT, ['cost' => 12]);
    }
    if (isset($b['ativo'])) {
        $sets[] = 'ativo = ?';
        $params[] = (int)(bool)$b['ativo'];
    }

    if (empty($sets)) err(400, 'Nenhum campo para atualizar.');

    $params[] = $uid;
    db()->prepare("UPDATE usuarios SET " . implode(', ', $sets) . " WHERE id = ?")
        ->execute($params);

    logAction($me['id'], 'editar_usuario', "Editou usuário id=$uid");
    ok(null, 'Usuário atualizado.');
}

// ── EXCLUIR USUÁRIO ────────────────────────────────────────
function routeExcluirUsuario(): never {
    global $path;
    $me  = auth(['superadmin','admin']);
    $uid = (int)(array_values(array_filter(explode('/', $path)))[1] ?? 0);

    $stmt = db()->prepare("SELECT role FROM usuarios WHERE id = ?");
    $stmt->execute([$uid]);
    $target = $stmt->fetch();
    if (!$target) err(404, 'Usuário não encontrado.');
    if ($target['role'] === 'superadmin') err(403, 'Não é possível excluir o superadmin.');
    if ($uid === $me['id']) err(400, 'Não é possível excluir a própria conta.');

    db()->prepare("DELETE FROM usuarios WHERE id = ?")->execute([$uid]);
    logAction($me['id'], 'excluir_usuario', "Excluiu usuário id=$uid");
    ok(null, 'Usuário excluído.');
}

// ── LISTAR CONTRACHEQUES ───────────────────────────────────
function routeListarCheques(): never {
    $me  = auth();
    $uid = (int)($_GET['usuario_id'] ?? 0);

    // colaborador só vê os próprios
    if ($me['role'] === 'colaborador') {
        $uid = $me['id'];
    }

    $where  = [];
    $params = [];

    if ($uid) {
        $where[]  = 'c.usuario_id = ?';
        $params[] = $uid;
    }

    // RH e colaborador não recebem o blob (apenas admin/superadmin ou o próprio)
    $selectBlob = in_array($me['role'], ['superadmin','admin','rh']) || $uid === $me['id']
        ? ', c.arquivo_dados'
        : '';

    $sql = "SELECT c.id, c.usuario_id, c.mes_referencia, c.nome_arquivo,
                   c.visualizado, c.data_visualizacao, c.criado_em,
                   u.nome_completo, u.matricula
                   $selectBlob
            FROM contracheques c
            JOIN usuarios u ON u.id = c.usuario_id"
         . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
         . ' ORDER BY c.criado_em DESC';

    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    ok($stmt->fetchAll());
}

// ── ENVIAR CONTRACHEQUE ────────────────────────────────────
function routeEnviarCheque(): never {
    $me = auth(['superadmin','admin']);
    $b  = body();

    $usuarioId   = (int)($b['usuario_id']     ?? 0);
    $mesRef      = sanitizeStr($b['mes_referencia'] ?? '');
    $nomeArquivo = sanitizeStr($b['nome_arquivo']   ?? 'contracheque.pdf');
    $arquivoDados = $b['arquivo_dados'] ?? ''; // base64 do PDF

    if (!$usuarioId || !$mesRef || !$arquivoDados)
        err(400, 'usuario_id, mes_referencia e arquivo_dados são obrigatórios.');

    // valida tamanho (~33% overhead do base64)
    $bytes = strlen($arquivoDados) * 0.75;
    if ($bytes > MAX_PDF_MB * 1024 * 1024)
        err(413, 'Arquivo excede o limite de ' . MAX_PDF_MB . ' MB.');

    // verifica se o usuário existe e é colaborador
    $check = db()->prepare("SELECT id FROM usuarios WHERE id = ? AND role = 'colaborador'");
    $check->execute([$usuarioId]);
    if (!$check->fetch()) err(404, 'Colaborador não encontrado.');

    $stmt = db()->prepare(
        "INSERT INTO contracheques (usuario_id, mes_referencia, nome_arquivo, arquivo_dados, enviado_por)
         VALUES (?,?,?,?,?)"
    );
    $stmt->execute([$usuarioId, $mesRef, $nomeArquivo, $arquivoDados, $me['id']]);
    $newId = (int)db()->lastInsertId();

    logAction($me['id'], 'enviar_cheque', "Enviou contracheque id=$newId para usuario_id=$usuarioId mes=$mesRef");
    ok(['id' => $newId], 'Contracheque enviado com sucesso.');
}

// ── MARCAR CIÊNCIA ─────────────────────────────────────────
function routeMarcarCiencia(): never {
    global $path;
    $me  = auth(['colaborador']);
    $cid = (int)(array_values(array_filter(explode('/', $path)))[1] ?? 0);

    $stmt = db()->prepare("SELECT id, usuario_id, visualizado FROM contracheques WHERE id = ?");
    $stmt->execute([$cid]);
    $cheque = $stmt->fetch();

    if (!$cheque) err(404, 'Contracheque não encontrado.');
    if ($cheque['usuario_id'] !== $me['id']) err(403, 'Acesso negado.');
    if ($cheque['visualizado']) err(409, 'Ciência já registrada.');

    db()->prepare(
        "UPDATE contracheques SET visualizado = 1, data_visualizacao = NOW() WHERE id = ?"
    )->execute([$cid]);

    logAction($me['id'], 'marcar_ciencia', "Marcou ciência no contracheque id=$cid");
    ok(['data_visualizacao' => date('d/m/Y H:i')], 'Ciência registrada.');
}

// ── EXCLUIR CONTRACHEQUE ───────────────────────────────────
function routeExcluirCheque(): never {
    global $path;
    $me  = auth(['superadmin','admin']);
    $cid = (int)(array_values(array_filter(explode('/', $path)))[1] ?? 0);

    $stmt = db()->prepare("SELECT id FROM contracheques WHERE id = ?");
    $stmt->execute([$cid]);
    if (!$stmt->fetch()) err(404, 'Contracheque não encontrado.');

    db()->prepare("DELETE FROM contracheques WHERE id = ?")->execute([$cid]);
    logAction($me['id'], 'excluir_cheque', "Excluiu contracheque id=$cid");
    ok(null, 'Contracheque excluído.');
}

// ── STATS ──────────────────────────────────────────────────
function routeStats(): never {
    auth(['superadmin','admin','rh']);

    $stats = db()->query("
        SELECT
          (SELECT COUNT(*) FROM usuarios WHERE role = 'colaborador' AND ativo = 1) AS colaboradores,
          (SELECT COUNT(*) FROM usuarios WHERE role IN ('superadmin','admin','rh') AND ativo = 1) AS privilegiados,
          (SELECT COUNT(*) FROM contracheques) AS total_cheques,
          (SELECT COUNT(*) FROM contracheques WHERE visualizado = 1) AS total_cientes,
          (SELECT COUNT(*) FROM contracheques WHERE visualizado = 0) AS total_pendentes
    ")->fetch();

    ok($stats);
}

// ── LOGS (somente superadmin) ──────────────────────────────
function routeLogs(): never {
    auth(['superadmin']);
    $limit = min((int)($_GET['limit'] ?? 100), 500);

    $stmt = db()->prepare("
        SELECT l.id, l.acao, l.descricao, l.ip, l.criado_em,
               u.username, u.nome_completo
        FROM log_acoes l
        LEFT JOIN usuarios u ON u.id = l.usuario_id
        ORDER BY l.criado_em DESC
        LIMIT ?
    ");
    $stmt->execute([$limit]);
    ok($stmt->fetchAll());
}
