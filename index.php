<?php
declare(strict_types=1);
session_start();

// Database setup
$db = new PDO('sqlite:' . __DIR__ . '/data.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Create tables
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    steam_id TEXT
)");
$db->exec("CREATE TABLE IF NOT EXISTS matches (
    match_id INTEGER PRIMARY KEY,
    data TEXT
)");
$db->exec("CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    match_id INTEGER,
    sentiment TEXT,
    stage TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE TABLE IF NOT EXISTS heroes (
    id INTEGER PRIMARY KEY,
    name TEXT,
    localized_name TEXT
)");

function get_heroes(PDO $db): array {
    $count = $db->query('SELECT COUNT(*) FROM heroes')->fetchColumn();
    if ($count == 0) {
        $json = @file_get_contents('https://api.opendota.com/api/heroes');
        if ($json) {
            $heroes = json_decode($json, true);
            $ins = $db->prepare('INSERT OR REPLACE INTO heroes(id, name, localized_name) VALUES(?,?,?)');
            foreach ($heroes as $h) {
                $ins->execute([$h['id'], $h['name'], $h['localized_name']]);
            }
        }
    }
    $heroes = [];
    foreach ($db->query('SELECT * FROM heroes') as $row) {
        $heroes[(int)$row['id']] = $row;
    }
    return $heroes;
}

$heroes = get_heroes($db);

function hero_image(string $name): string {
    $short = str_replace('npc_dota_hero_', '', $name);
    return "https://cdn.cloudflare.steamstatic.com/apps/dota2/images/dota_react/heroes/{$short}.png";
}

function cache_match(PDO $db, int $match_id): void {
    $stmt = $db->prepare('SELECT 1 FROM matches WHERE match_id=?');
    $stmt->execute([$match_id]);
    if (!$stmt->fetchColumn()) {
        $json = @file_get_contents("https://api.opendota.com/api/matches/{$match_id}");
        if ($json) {
            $ins = $db->prepare('INSERT INTO matches(match_id, data) VALUES(?,?)');
            $ins->execute([$match_id, $json]);
        }
    }
}

function get_match(PDO $db, int $match_id): ?array {
    cache_match($db, $match_id);
    $stmt = $db->prepare('SELECT data FROM matches WHERE match_id=?');
    $stmt->execute([$match_id]);
    $json = $stmt->fetchColumn();
    return $json ? json_decode($json, true) : null;
}

function get_user(PDO $db, int $id): ?array {
    $stmt = $db->prepare('SELECT * FROM users WHERE id=?');
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

// Handle actions
$action = $_GET['action'] ?? '';
$error = '';
if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    if ($username && $password) {
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $db->prepare('INSERT INTO users(username, password) VALUES(?,?)');
        try {
            $stmt->execute([$username, $hash]);
            $_SESSION['user_id'] = (int)$db->lastInsertId();
            header('Location: index.php');
            exit;
        } catch (PDOException $e) {
            $error = 'Username already exists';
        }
    }
} elseif ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $stmt = $db->prepare('SELECT * FROM users WHERE username=?');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = (int)$user['id'];
        header('Location: index.php');
        exit;
    } else {
        $error = 'Invalid credentials';
    }
} elseif ($action === 'logout') {
    session_destroy();
    header('Location: index.php');
    exit;
} elseif ($action === 'set_steam_id' && isset($_SESSION['user_id']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $steam_id = trim($_POST['steam_id'] ?? '');
    $stmt = $db->prepare('UPDATE users SET steam_id=? WHERE id=?');
    $stmt->execute([$steam_id, $_SESSION['user_id']]);
    header('Location: index.php');
    exit;
} elseif ($action === 'add_note' && isset($_SESSION['user_id']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $match_id = (int)($_POST['match_id'] ?? 0);
    $sentiment = $_POST['sentiment'] ?? 'positive';
    $stage = $_POST['stage'] ?? 'Early';
    $content = trim($_POST['content'] ?? '');
    if ($match_id && $content) {
        cache_match($db, $match_id);
        $stmt = $db->prepare('INSERT INTO notes(user_id, match_id, sentiment, stage, content) VALUES(?,?,?,?,?)');
        $stmt->execute([$_SESSION['user_id'], $match_id, $sentiment, $stage, $content]);
    }
    header('Location: index.php?page=match&match_id=' . $match_id);
    exit;
} elseif ($action === 'edit_note' && isset($_SESSION['user_id']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $note_id = (int)($_POST['note_id'] ?? 0);
    $sentiment = $_POST['sentiment'] ?? 'positive';
    $stage = $_POST['stage'] ?? 'Early';
    $content = trim($_POST['content'] ?? '');
    $stmt = $db->prepare('UPDATE notes SET sentiment=?, stage=?, content=? WHERE id=? AND user_id=?');
    $stmt->execute([$sentiment, $stage, $content, $note_id, $_SESSION['user_id']]);
    $match_id = (int)($_POST['match_id'] ?? 0);
    header('Location: index.php?page=match&match_id=' . $match_id);
    exit;
} elseif ($action === 'delete_note' && isset($_SESSION['user_id']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $note_id = (int)($_POST['note_id'] ?? 0);
    $match_id = (int)($_POST['match_id'] ?? 0);
    $stmt = $db->prepare('DELETE FROM notes WHERE id=? AND user_id=?');
    $stmt->execute([$note_id, $_SESSION['user_id']]);
    header('Location: index.php?page=match&match_id=' . $match_id);
    exit;
}

// Helpers for fetching matches and notes
function get_recent_matches(string $steam_id): array {
    $json = @file_get_contents("https://api.opendota.com/api/players/{$steam_id}/recentMatches");
    return $json ? json_decode($json, true) : [];
}

function get_notes(PDO $db, int $user_id, ?int $match_id = null): array {
    if ($match_id) {
        $stmt = $db->prepare('SELECT * FROM notes WHERE user_id=? AND match_id=? ORDER BY created_at DESC');
        $stmt->execute([$user_id, $match_id]);
    } else {
        $stmt = $db->prepare('SELECT * FROM notes WHERE user_id=? ORDER BY created_at DESC');
        $stmt->execute([$user_id]);
    }
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$user = isset($_SESSION['user_id']) ? get_user($db, (int)$_SESSION['user_id']) : null;
$page = $_GET['page'] ?? 'home';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dota Notes</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="index.php">Dota Notes</a>
    <div class="d-flex">
    <?php if ($user): ?>
        <span class="navbar-text text-white me-3">Hello, <?=htmlspecialchars($user['username'])?></span>
        <a class="btn btn-outline-light" href="index.php?action=logout">Logout</a>
    <?php endif; ?>
    </div>
  </div>
</nav>
<div class="container">
<?php if (!$user): ?>
    <div class="row">
        <div class="col-md-6">
            <h3>Login</h3>
            <?php if ($error && $action==='login'): ?><div class="alert alert-danger"><?=htmlspecialchars($error)?></div><?php endif; ?>
            <form method="post" action="index.php?action=login">
                <div class="mb-3">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                <button class="btn btn-primary">Login</button>
            </form>
        </div>
        <div class="col-md-6">
            <h3>Register</h3>
            <?php if ($error && $action==='register'): ?><div class="alert alert-danger"><?=htmlspecialchars($error)?></div><?php endif; ?>
            <form method="post" action="index.php?action=register">
                <div class="mb-3">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                <button class="btn btn-success">Register</button>
            </form>
        </div>
    </div>
<?php else: ?>
    <?php if (!$user['steam_id']): ?>
        <div class="row">
            <div class="col-md-6">
                <h3>Enter Steam ID</h3>
                <form method="post" action="index.php?action=set_steam_id">
                    <div class="mb-3">
                        <label class="form-label">Steam ID (32-bit)</label>
                        <input type="text" name="steam_id" class="form-control" required>
                    </div>
                    <button class="btn btn-primary">Save</button>
                </form>
            </div>
        </div>
    <?php else: ?>
        <?php if ($page === 'match' && isset($_GET['match_id'])): ?>
            <?php $match_id = (int)$_GET['match_id']; $match = get_match($db, $match_id); ?>
            <?php if ($match): ?>
                <?php
                    $notes = get_notes($db, $user['id'], $match_id);
                    $player = null;
                    foreach ($match['players'] as $p) {
                        if ((string)$p['account_id'] === $user['steam_id']) { $player = $p; break; }
                    }
                ?>
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h3>Match <?=htmlspecialchars((string)$match_id)?></h3>
                    <a class="btn btn-secondary" href="index.php">Back to matches</a>
                </div>
                <?php if ($player): ?>
                <div class="card mb-3">
                    <div class="card-body">
                        <h5 class="card-title">Your Performance</h5>
                        <p class="card-text">Hero: <?=htmlspecialchars($heroes[$player['hero_id']]['localized_name'] ?? '')?></p>
                        <p class="card-text">K/D/A: <?=$player['kills']?>/<?=$player['deaths']?>/<?=$player['assists']?></p>
                        <p class="card-text">Net Worth: <?=$player['net_worth']?></p>
                    </div>
                </div>
                <?php endif; ?>
                <button class="btn btn-primary mb-3" data-bs-toggle="modal" data-bs-target="#addNoteModal">Add Note</button>
                <?php if ($notes): ?>
                    <?php foreach ($notes as $n): ?>
                        <div class="card mb-2">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <h5 class="card-title">
                                        <?=htmlspecialchars($n['stage'])?> - <?=htmlspecialchars($n['sentiment'])?>
                                    </h5>
                                    <div>
                                        <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#editNoteModal<?=$n['id']?>">Edit</button>
                                        <button class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteNoteModal<?=$n['id']?>">Delete</button>
                                    </div>
                                </div>
                                <p class="card-text"><?=nl2br(htmlspecialchars($n['content']))?></p>
                            </div>
                        </div>
                        <!-- Edit Modal -->
                        <div class="modal fade" id="editNoteModal<?=$n['id']?>" tabindex="-1" aria-hidden="true">
                          <div class="modal-dialog">
                            <form class="modal-content" method="post" action="index.php?action=edit_note">
                              <div class="modal-header">
                                <h5 class="modal-title">Edit Note</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                              </div>
                              <div class="modal-body">
                                <input type="hidden" name="note_id" value="<?=$n['id']?>">
                                <input type="hidden" name="match_id" value="<?=$match_id?>">
                                <div class="mb-3">
                                    <label class="form-label">Sentiment</label>
                                    <select name="sentiment" class="form-select">
                                        <option value="positive" <?=$n['sentiment']==='positive'?'selected':''?>>Positive</option>
                                        <option value="negative" <?=$n['sentiment']==='negative'?'selected':''?>>Negative</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Stage</label>
                                    <select name="stage" class="form-select">
                                        <?php foreach(['Early','Mid','Late'] as $s): ?>
                                            <option value="<?=$s?>" <?=$n['stage']===$s?'selected':''?>><?=$s?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Content</label>
                                    <textarea name="content" class="form-control" required><?=htmlspecialchars($n['content'])?></textarea>
                                </div>
                              </div>
                              <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                <button class="btn btn-primary">Save changes</button>
                              </div>
                            </form>
                          </div>
                        </div>
                        <!-- Delete Modal -->
                        <div class="modal fade" id="deleteNoteModal<?=$n['id']?>" tabindex="-1" aria-hidden="true">
                          <div class="modal-dialog">
                            <form class="modal-content" method="post" action="index.php?action=delete_note">
                              <div class="modal-header">
                                <h5 class="modal-title">Delete Note</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                              </div>
                              <div class="modal-body">
                                Are you sure you want to delete this note?
                                <input type="hidden" name="note_id" value="<?=$n['id']?>">
                                <input type="hidden" name="match_id" value="<?=$match_id?>">
                              </div>
                              <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button class="btn btn-danger">Delete</button>
                              </div>
                            </form>
                          </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p>No notes yet.</p>
                <?php endif; ?>
                <!-- Add Note Modal -->
                <div class="modal fade" id="addNoteModal" tabindex="-1" aria-hidden="true">
                  <div class="modal-dialog">
                    <form class="modal-content" method="post" action="index.php?action=add_note">
                      <div class="modal-header">
                        <h5 class="modal-title">Add Note</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                      </div>
                      <div class="modal-body">
                        <input type="hidden" name="match_id" value="<?=$match_id?>">
                        <div class="mb-3">
                            <label class="form-label">Sentiment</label>
                            <select name="sentiment" class="form-select">
                                <option value="positive">Positive</option>
                                <option value="negative">Negative</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Stage</label>
                            <select name="stage" class="form-select">
                                <option>Early</option>
                                <option>Mid</option>
                                <option>Late</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Content</label>
                            <textarea name="content" class="form-control" required></textarea>
                        </div>
                      </div>
                      <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button class="btn btn-primary">Add Note</button>
                      </div>
                    </form>
                  </div>
                </div>
            <?php else: ?>
                <p>Match data not available.</p>
            <?php endif; ?>
        <?php else: ?>
            <?php $matches = get_recent_matches($user['steam_id']); ?>
            <h3>Recent Matches</h3>
            <?php if (!$matches): ?>
                <p>No match data available.</p>
            <?php else: ?>
            <div class="row row-cols-1 row-cols-md-2 g-4">
            <?php foreach ($matches as $m): 
                $hero = $heroes[$m['hero_id']] ?? null; 
                $img = $hero ? hero_image($hero['name']) : ''; 
                $notes = get_notes($db, $user['id'], (int)$m['match_id']);
            ?>
                <div class="col">
                    <div class="card h-100">
                        <?php if ($img): ?><img src="<?=$img?>" class="card-img-top" alt="Hero">
                        <?php endif; ?>
                        <div class="card-body">
                            <h5 class="card-title">Match <?=$m['match_id']?></h5>
                            <p class="card-text">Hero: <?=htmlspecialchars($hero['localized_name'] ?? 'Unknown')?></p>
                            <p class="card-text">K/D/A: <?=$m['kills']?>/<?=$m['deaths']?>/<?=$m['assists']?></p>
                            <p class="card-text">Notes: <?=count($notes)?></p>
                            <a class="btn btn-primary" href="index.php?page=match&match_id=<?=$m['match_id']?>">View</a>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
            </div>
            <?php endif; ?>
        <?php endif; ?>
    <?php endif; ?>
<?php endif; ?>
</div>
</body>
</html>
