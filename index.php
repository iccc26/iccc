<?php
/**
 * Iranian Civil Community CIC — admin panel
 * Support cases, volunteers, partnership enquiries and messages in one place.
 */
declare(strict_types=1);
require dirname(__DIR__) . '/api/lib.php';

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, private');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'");

iccc_session();
$config = iccc_config();

/* ------------------------------------------------------------ IP allowlist */
if (!empty($config['admin_ip_allowlist'])
    && !in_array($_SERVER['REMOTE_ADDR'] ?? '', $config['admin_ip_allowlist'], true)) {
    http_response_code(403);
    exit('Access denied.');
}

/* ------------------------------------------------------------------ logout */
if (isset($_GET['logout'])) {
    iccc_audit('admin.logout');
    $_SESSION = [];
    session_destroy();
    header('Location: index.php');
    exit;
}

/* ------------------------------------------------------------------- login */
$loginError = '';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['login_user'])) {
    $throttleFile = iccc_storage('ratelimit') . '/admin-' . sha1($_SERVER['REMOTE_ADDR'] ?? '') . '.json';
    $attempts = is_file($throttleFile) ? (json_decode((string) file_get_contents($throttleFile), true) ?: []) : [];
    $attempts = array_values(array_filter($attempts, fn($t) => $t > time() - 900));

    if (count($attempts) >= 5) {
        $loginError = 'تلاش‌های ناموفق زیاد است. ۱۵ دقیقه صبر کنید.';
    } elseif (!iccc_csrf_check((string) ($_POST['_csrf'] ?? ''))) {
        $loginError = 'نشست منقضی شده است. دوباره تلاش کنید.';
    } else {
        $user = (string) $_POST['login_user'];
        $pass = (string) ($_POST['login_pass'] ?? '');
        $hash = $config['admin_users'][$user] ?? '';
        if ($hash !== '' && password_verify($pass, $hash)) {
            session_regenerate_id(true);
            $_SESSION['admin_user'] = $user;
            $_SESSION['created']    = time();
            @unlink($throttleFile);
            iccc_audit('admin.login');
            header('Location: index.php');
            exit;
        }
        $attempts[] = time();
        file_put_contents($throttleFile, json_encode($attempts), LOCK_EX);
        iccc_audit('admin.login_failed', $user);
        $loginError = 'نام کاربری یا رمز عبور درست نیست.';
    }
}

$authed = !empty($_SESSION['admin_user']);

/* ----------------------------------------------- authenticated actions */
if ($authed && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['action'])) {
    if (!iccc_csrf_check((string) ($_POST['_csrf'] ?? ''))) {
        http_response_code(419);
        exit('Session expired.');
    }
    $type = preg_replace('/[^a-z]/', '', (string) ($_POST['type'] ?? ''));
    $id   = basename((string) ($_POST['id'] ?? ''));

    if ($_POST['action'] === 'status') {
        $record = iccc_read_record($type, $id);
        if ($record) {
            $record['status']     = in_array($_POST['status'] ?? '', ['new', 'in_progress', 'answered', 'closed'], true)
                ? $_POST['status'] : 'new';
            $record['updated_at'] = gmdate('c');
            $file = iccc_storage('records/' . $type) . '/' . $id . '.enc';
            file_put_contents($file, iccc_encrypt(json_encode($record, JSON_UNESCAPED_UNICODE)), LOCK_EX);
            iccc_audit('record.status', $type . '/' . $id . ' → ' . $record['status']);
        }
    }

    if ($_POST['action'] === 'delete') {
        $record = iccc_read_record($type, $id);
        foreach (($record['files'] ?? []) as $f) {
            @unlink(iccc_storage('uploads') . '/' . basename($f['blob']));
        }
        @unlink(iccc_storage('records/' . $type) . '/' . $id . '.enc');
        iccc_audit('record.deleted', $type . '/' . $id);
        header('Location: index.php?type=' . urlencode($type));
        exit;
    }
    header('Location: index.php?type=' . urlencode($type) . '&id=' . urlencode($id));
    exit;
}

/* ------------------------------------------------- encrypted file download */
if ($authed && isset($_GET['download'], $_GET['type'], $_GET['id'])) {
    $record = iccc_read_record(preg_replace('/[^a-z]/', '', $_GET['type']), basename($_GET['id']));
    $wanted = basename((string) $_GET['download']);
    foreach (($record['files'] ?? []) as $f) {
        if ($f['blob'] === $wanted) {
            $blob = iccc_storage('uploads') . '/' . $wanted;
            if (!is_file($blob)) {
                break;
            }
            iccc_audit('file.downloaded', $record['reference'] . '/' . $f['original_name']);
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $f['original_name'] . '"');
            header('X-Content-Type-Options: nosniff');
            echo iccc_decrypt((string) file_get_contents($blob));
            exit;
        }
    }
    http_response_code(404);
    exit('Not found.');
}

$csrf  = iccc_csrf_token();
$types = ['support' => 'درخواست حمایت', 'volunteer' => 'داوطلبان', 'partner' => 'همکاری', 'contact' => 'پیام‌ها'];
$type  = isset($_GET['type'], $types[$_GET['type']]) ? $_GET['type'] : 'support';
$open  = isset($_GET['id']) ? iccc_read_record($type, basename($_GET['id'])) : null;
if ($open) {
    iccc_audit('record.viewed', $type . '/' . basename($_GET['id']));
}

function e(?string $v): string { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>پنل مدیریت — Iranian Civil Community CIC</title>
<style>
:root{--ink:#12263F;--green:#14603A;--red:#B3282D;--paper:#F7F7F4;--hair:#DFE3DC;--slate:#57636E}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:Vazirmatn,Tahoma,system-ui,sans-serif;font-size:15px;line-height:1.8}
header{background:var(--ink);color:#fff;padding:.9rem 1.2rem;display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
header b{font-size:1rem}
header .spacer{margin-inline-start:auto}
header a{color:#C9D4E0}
.wrap{max-width:1150px;margin:0 auto;padding:1.4rem 1rem 3rem}
.tabs{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:1.1rem}
.tabs a{padding:.5rem 1rem;border:1px solid var(--hair);background:#fff;border-radius:6px;text-decoration:none;color:var(--ink);font-size:.93rem}
.tabs a.on{background:var(--ink);color:#fff;border-color:var(--ink)}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--hair);border-radius:8px;overflow:hidden}
th,td{padding:.7rem .8rem;text-align:start;border-bottom:1px solid var(--hair);font-size:.92rem;vertical-align:top}
th{background:#F1F3EE;font-weight:600}
tr:last-child td{border-bottom:0}
a.ref{font-family:ui-monospace,Menlo,monospace;color:var(--green);font-weight:700;text-decoration:none}
.badge{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.78rem;border:1px solid var(--hair);background:#fff}
.badge.new{background:#FBEDED;border-color:#EFC9CA;color:#8E2226}
.badge.in_progress{background:#FEF6E3;border-color:#EBD79B;color:#7A5B12}
.badge.answered,.badge.closed{background:#EAF5EE;border-color:#BCDFC8;color:#14603A}
.card{background:#fff;border:1px solid var(--hair);border-radius:8px;padding:1.2rem;margin-bottom:1rem}
.card h2{margin:.1rem 0 1rem;font-size:1.05rem}
.kv{display:grid;grid-template-columns:190px 1fr;gap:.5rem 1rem;font-size:.94rem}
.kv div:nth-child(odd){color:var(--slate)}
pre.story{white-space:pre-wrap;background:var(--paper);border:1px solid var(--hair);border-radius:6px;padding:.9rem;font:inherit;margin:.6rem 0 0}
.files a{display:inline-flex;gap:.5rem;align-items:center;border:1px solid var(--hair);border-radius:6px;padding:.45rem .8rem;margin:.25rem .25rem 0 0;text-decoration:none;color:var(--ink);font-size:.9rem;background:#fff}
button,select{font:inherit;border-radius:6px;border:1px solid var(--hair);padding:.45rem .8rem;background:#fff;cursor:pointer}
button.primary{background:var(--ink);color:#fff;border-color:var(--ink)}
button.danger{background:#fff;color:var(--red);border-color:#EFC9CA}
.login{max-width:380px;margin:9vh auto;background:#fff;border:1px solid var(--hair);border-radius:10px;padding:1.6rem}
.login h1{font-size:1.1rem;margin:0 0 1.2rem}
.login input{width:100%;padding:.6rem .7rem;border:1px solid var(--hair);border-radius:6px;font:inherit;margin-bottom:.9rem}
.err{background:#FBEDED;border:1px solid #EFC9CA;color:#8E2226;padding:.6rem .8rem;border-radius:6px;margin-bottom:1rem;font-size:.9rem}
.muted{color:var(--slate);font-size:.88rem}
@media(max-width:700px){.kv{grid-template-columns:1fr}.kv div:nth-child(odd){font-weight:600}}
</style>
</head>
<body>

<?php if (!$authed): ?>
  <form class="login" method="post">
    <h1>ورود به پنل مدیریت</h1>
    <?php if ($loginError): ?><div class="err"><?= e($loginError) ?></div><?php endif; ?>
    <input type="hidden" name="_csrf" value="<?= e($csrf) ?>">
    <label for="u">نام کاربری</label>
    <input id="u" name="login_user" autocomplete="username" required>
    <label for="p">رمز عبور</label>
    <input id="p" name="login_pass" type="password" autocomplete="current-password" required>
    <button class="primary" type="submit" style="width:100%">ورود</button>
    <p class="muted" style="margin-bottom:0">هر ورود و هر بار مشاهده پرونده در فایل audit.log ثبت می‌شود.</p>
  </form>

<?php else: ?>
  <header>
    <b>پنل مدیریت — Iranian Civil Community CIC</b>
    <span class="spacer"></span>
    <span class="muted" style="color:#C9D4E0"><?= e($_SESSION['admin_user']) ?></span>
    <a href="?logout=1">خروج</a>
  </header>

  <div class="wrap">
    <nav class="tabs">
      <?php foreach ($types as $key => $label): ?>
        <a href="?type=<?= e($key) ?>" class="<?= $key === $type ? 'on' : '' ?>">
          <?= e($label) ?> (<?= count(iccc_list_records($key)) ?>)
        </a>
      <?php endforeach; ?>
    </nav>

    <?php if ($open): ?>
      <div class="card">
        <h2>پرونده <?= e($open['reference'] ?? '') ?>
          <span class="badge <?= e($open['status'] ?? 'new') ?>"><?= e($open['status'] ?? 'new') ?></span>
        </h2>
        <div class="kv">
          <?php
          $labels = [
              'created_at' => 'تاریخ دریافت', 'alias' => 'نام / نام مستعار', 'name' => 'نام',
              'organisation' => 'سازمان', 'person' => 'فرد تماس', 'role' => 'سمت',
              'email' => 'ایمیل', 'phone' => 'تلفن', 'channel' => 'راه تماس دیگر',
              'reply_lang' => 'زبان پاسخ', 'country' => 'کشور', 'city' => 'شهر',
              'situation' => 'وضعیت', 'needs' => 'نیازها', 'languages' => 'زبان‌ها',
              'skills' => 'تخصص', 'availability' => 'زمان در دسترس', 'website' => 'وب‌سایت',
              'collab_type' => 'نوع همکاری', 'subject' => 'موضوع', 'form_lang' => 'زبان فرم',
          ];
          foreach ($labels as $key => $label):
              if (empty($open[$key])) continue;
              $value = is_array($open[$key]) ? implode('، ', $open[$key]) : $open[$key]; ?>
              <div><?= e($label) ?></div><div><?= e((string) $value) ?></div>
          <?php endforeach; ?>
        </div>

        <?php foreach (['story' => 'شرح وضعیت', 'about' => 'توضیح', 'proposal' => 'پیشنهاد', 'message' => 'پیام'] as $key => $label): ?>
          <?php if (!empty($open[$key])): ?>
            <p style="margin:1rem 0 0"><b><?= e($label) ?></b></p>
            <pre class="story"><?= e($open[$key]) ?></pre>
          <?php endif; ?>
        <?php endforeach; ?>

        <?php if (!empty($open['files'])): ?>
          <p style="margin:1.1rem 0 .2rem"><b>مدارک پیوست</b> <span class="muted">(رمزگشایی هنگام دانلود، هر دانلود ثبت می‌شود)</span></p>
          <div class="files">
            <?php foreach ($open['files'] as $f): ?>
              <a href="?type=<?= e($type) ?>&id=<?= e(basename($_GET['id'])) ?>&download=<?= e($f['blob']) ?>">
                📎 <?= e($f['original_name']) ?> — <?= (int) round($f['size'] / 1024) ?> KB
              </a>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>

        <div style="display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1.3rem;align-items:center">
          <form method="post" style="display:flex;gap:.5rem">
            <input type="hidden" name="_csrf" value="<?= e($csrf) ?>">
            <input type="hidden" name="action" value="status">
            <input type="hidden" name="type" value="<?= e($type) ?>">
            <input type="hidden" name="id" value="<?= e(basename($_GET['id'])) ?>">
            <select name="status">
              <?php foreach (['new' => 'جدید', 'in_progress' => 'در دست بررسی', 'answered' => 'پاسخ داده شد', 'closed' => 'بسته شد'] as $v => $l): ?>
                <option value="<?= e($v) ?>" <?= ($open['status'] ?? '') === $v ? 'selected' : '' ?>><?= e($l) ?></option>
              <?php endforeach; ?>
            </select>
            <button class="primary" type="submit">ثبت وضعیت</button>
          </form>

          <form method="post" onsubmit="return confirm('این پرونده و همه فایل‌های آن برای همیشه حذف شود؟')">
            <input type="hidden" name="_csrf" value="<?= e($csrf) ?>">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="type" value="<?= e($type) ?>">
            <input type="hidden" name="id" value="<?= e(basename($_GET['id'])) ?>">
            <button class="danger" type="submit">حذف پرونده</button>
          </form>

          <a href="?type=<?= e($type) ?>" style="margin-inline-start:auto">بازگشت به فهرست</a>
        </div>
      </div>
    <?php endif; ?>

    <?php $ids = iccc_list_records($type); ?>
    <table>
      <thead>
        <tr><th>کد پیگیری</th><th>تاریخ</th><th>فرستنده</th><th>خلاصه</th><th>وضعیت</th></tr>
      </thead>
      <tbody>
      <?php if (!$ids): ?>
        <tr><td colspan="5" class="muted">هنوز موردی در این بخش ثبت نشده است.</td></tr>
      <?php endif; ?>
      <?php foreach ($ids as $id):
          $r = iccc_read_record($type, $id);
          if (!$r) continue;
          $who     = $r['alias'] ?? $r['name'] ?? $r['organisation'] ?? '—';
          $summary = $r['story'] ?? $r['skills'] ?? $r['proposal'] ?? $r['message'] ?? '';
          $summary = function_exists('mb_substr') ? mb_substr($summary, 0, 90) : substr($summary, 0, 90); ?>
        <tr>
          <td><a class="ref" href="?type=<?= e($type) ?>&id=<?= e($id) ?>"><?= e($r['reference'] ?? $id) ?></a></td>
          <td class="muted"><?= e(substr((string) ($r['created_at'] ?? ''), 0, 16)) ?></td>
          <td><?= e($who) ?><?= !empty($r['files']) ? ' 📎' : '' ?></td>
          <td class="muted"><?= e($summary) ?><?= $summary !== '' ? '…' : '' ?></td>
          <td><span class="badge <?= e($r['status'] ?? 'new') ?>"><?= e($r['status'] ?? 'new') ?></span></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>

    <p class="muted" style="margin-top:1.2rem">
      پرونده‌ها رمزگذاری‌شده بیرون از پوشه عمومی وب نگهداری می‌شوند. فایل audit.log هر ورود، مشاهده، دانلود و حذف را ثبت می‌کند.
    </p>
  </div>
<?php endif; ?>

</body>
</html>
