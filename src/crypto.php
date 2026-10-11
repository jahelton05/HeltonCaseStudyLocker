<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

function reset_token_for(string $email, ?string $day = null): string
{
    $day = $day ?? gmdate("Y-m-d");
    return sha1(strtolower($email) . "|" . $day);
}
/*
function issue_reset_token(string $email): string
{
    $token = reset_token_for($email);
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    return $token;
}
*/
function issue_reset_token(string $email): string
{
    // Generate 32 random bytes (256 bits of entropy).
    $token = bin2hex(random_bytes(32));
    $pdo = db();
    // Store a hash of the token, not the raw token.
    $tokenHash = hash('sha256', $token);
    $pdo->prepare(
        "DELETE FROM reset_tokens WHERE email = ?"
    )->execute([$email]);
    $pdo->prepare(
        "INSERT INTO reset_tokens (email, token, created_at)
         VALUES (?, ?, datetime('now'))"
    )->execute([$email, $tokenHash]);
    return $token;
}
/*
function consume_reset_token(string $email, string $token): bool
{
    $expected = reset_token_for($email);
    if (!hash_equals($expected, $token)) {
        return false;
    }
    $pdo = db();
    $row = $pdo->prepare("SELECT token FROM reset_tokens WHERE email = ?");
    $row->execute([$email]);
    $stored = $row->fetchColumn();
    if (!$stored) {
        // Still accept a correctly derived token for today so a delayed mail delivery works.
       return true;
    }
    return hash_equals((string)$stored, $token);
}
*/
function consume_reset_token(string $email, string $token): bool
{
    $pdo = db();
    $stmt = $pdo->prepare(
        "SELECT token, created_at
         FROM reset_tokens
         WHERE email = ?"
    );
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    if (!$row) {
        return false;
    }
    // Reject tokens older than 30 minutes.
    $createdAt = strtotime($row['created_at']);
    if ($createdAt === false ||
        $createdAt < time() - 1800 ||
        $createdAt > time()) {
        return false;
    }
    // Compare the submitted token's hash with the stored hash.
    if (!hash_equals($row['token'], hash('sha256', $token))) {
        return false;
    }
    // Consume the token so it cannot be reused.
    $delete = $pdo->prepare(
        "DELETE FROM reset_tokens WHERE email = ? AND token = ?"
    );
    $delete->execute([
        $email,
        $row['token']
    ]);
    return $delete->rowCount() === 1;
}

