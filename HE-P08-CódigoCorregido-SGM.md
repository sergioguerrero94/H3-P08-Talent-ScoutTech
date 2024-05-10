# Código Corregido - Talent ScoutTech

## Indice

- [Resumen ejecutivo](#resumen-ejecutivo)
- [Código Sanitizado](#código-sanitizado)
    - [Register.php](#registerphp)
    - [Aut.php](#authphp)
    - [Show_Comments.php](#show_commentsphp)
    - [Insert_player.php](#insert_playerphp)
    - [Add_comment](#add_commentphp)


## Resumen Ejecutivo

En este documento se especifica una serie de códigos sanitizados de los distintos códigos .php recibidos para el pentesting de la aplicación Talent ScoutTech.

## Código Sanitizado

### Register.php

En este punto se indica el código de register.php sanitizado para crear un registro seguro.

```
<?php
require_once dirname(__FILE__) . '/private/conf.php';

if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validación de entrada
    if (strlen($username) < 4 || strlen($username) > 20) {
        die("Username must be between 4 and 20 characters long.");
    }

    if (strlen($password) < 6) {
        die("Password must be at least 6 characters long.");
    }

    // Sanitización de entrada
    $username = filter_var($username, FILTER_SANITIZE_STRING);
    // No es necesario sanitizar la contraseña, ya que la vamos a hashear más adelante

    // Consulta preparada
    $query = "INSERT INTO users (username, password) VALUES (:username, :password)";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $username);
    
    // Hasheamos la contraseña antes de almacenarla
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt->bindParam(':password', $hashed_password);

    // Ejecutar la consulta
    if ($stmt->execute()) {
        header("Location: list_players.php");
        exit();
    } else {
        die("Error executing query.");
    }
}
?>

<!doctype html>
<html lang="es">
    <head>
        <!-- Encabezado omitido por brevedad -->
    </head>
    <body>
        <header>
            <h1>Register</h1>
        </header>
        <main class="player">
            <form action="#" method="post">
                <!-- Formulario omitido por brevedad -->
            </form>
            <form action="#" method="post" class="menu-form">
                <a href="list_players.php">Back to list</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </main>
        <footer class="listado">
            <!-- Pie de página omitido por brevedad -->
        </footer>
    </body>
</html>
```

### Auth.php

En este punto se indica el código de auth.php sanitizado para crear una autenticación segura en nuestra aplicación.

```
<?php
require_once dirname(__FILE__) . '/conf.php';

$userId = FALSE;

# Check whether a pair of user and password are valid; returns true if valid.
function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    $query = "SELECT userId, password FROM users WHERE username = :username";
    $stmt = $db->prepare($query);
    $stmt->bindValue(':username', $user);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row && password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        return true;
    } else {
        return false;
    }
}

# On login
if (isset($_POST['username']) && isset($_POST['password'])) {        
    if (areUserAndPasswordValid($_POST['username'], $_POST['password'])) {
        session_start();
        $_SESSION['user'] = $_POST['username'];
        header("Location: index.php");
        exit();
    } else {
        $error = "Invalid user or password.<br>";
    }
}

# On logout
if (isset($_POST['Logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}

if (!isset($_SESSION['user'])) {
?>
<!doctype html>
<html lang="es">
<head>
    <!-- Encabezado omitido por brevedad -->
</head>
<body>
<header class="auth">
    <h1>Authentication page</h1>
</header>
<section class="auth">
    <div class="message">
        <?= isset($error) ? $error : "" ?>
    </div>
    <section>
        <div>
            <h2>Login</h2>
            <form action="#" method="post">
                <label>User</label>
                <input type="text" name="username"><br>
                <label>Password</label>
                <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
        </div>

        <div>
            <h2>Logout</h2>
            <form action="#" method="post">
                <input type="submit" name="Logout" value="Logout">
            </form>
        </div>
    </section>
</section>
<footer>
    <!-- Pie de página omitido por brevedad -->
</footer>
</body>
</html>
<?php
    exit();
}

$_SESSION['user'] = $_POST['username'];
?>
```

### Show_Comments.php

En este punto se indica el código sanitizado de show_comments.php para que no se pueda ejecutar en él ataques XSS.

```
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments editor</title>
</head>
<body>
<header>
    <h1>Comments editor</h1>
</header>
<main class="player">

<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

# List comments
if (isset($_GET['id']))
{
    $query = "SELECT commentId, username, body FROM comments C, users U WHERE C.playerId =".$_GET['id']." AND U.userId = C.userId order by C.playerId desc";

    $result = $db->query($query) or die("Invalid query: " . $query );

    while ($row = $result->fetchArray()) {
        echo "<div>
                <h4> ". $row['username'] ."</h4> 
                <p>commented: " . $row['body'] . "</p>
              </div>";
    }

    $playerId = $_GET['id'];
}

# Show form

?>

<div>
    <a href="list_players.php">Back to list</a>
    <a class="black" href="add_comment.php?id=<?php echo htmlspecialchars($playerId); ?>">Add comment</a>
</div>

</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>
```

### Insert_player.php

en este punto se indica el código sanitizado de insert_player.php para no permitir ataques XSS.

```
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

$id = isset($_GET['id']) ? $_GET['id'] : null;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (isset($_POST['name'], $_POST['team'])) {
        # Just in from POST => save to database
        $name = htmlspecialchars($_POST['name']);
        $team = htmlspecialchars($_POST['team']);

        // Modify player or add a new one
        if ($id) {
            $query = "INSERT OR REPLACE INTO players (playerid, name, team) VALUES ('$id', '$name', '$team')";
        } else {
            $query = "INSERT INTO players (name, team) VALUES ('$name', '$team')";
        }

        $db->query($query) or die("Invalid query");
    }
} else {
    # Show info to modify
    if ($id) {
        # Edit from database
        $query ="SELECT name, team FROM players WHERE playerid = '$id'";
        $result = $db->query($query) or die ("Invalid query");
        $row = $result->fetchArray();

        if ($row) {
            $name = htmlspecialchars($row['name']);
            $team = htmlspecialchars($row['team']);
        } else {
            die ("Modifying a nonexistent player!");
        }
    }
}

# Show form
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Players list</title>
</head>
<body>
<header>
    <h1>Player</h1>
</header>
<main class="player">
    <form action="#" method="post">
        <input type="hidden" name="id" value="<?=$id?>"><br>
        <h3>Player name</h3>
        <textarea name="name"><?=$name?></textarea><br>
        <h3>Team name</h3>
        <textarea name="team"><?=$team?></textarea><br>
        <input type="submit" value="Send">
    </form>
    <form action="#" method="post" class="menu-form">
        <a href="index.php">Back to home</a>
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>
```

## Add_comment.php

En este punto se especifica el código corregido para protegerse de ataques Web.

```
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['body'], $_GET['id'])) {
    # Just in from POST => save to database
    $body = $_POST['body'];

    $stmt = $db->prepare("INSERT INTO comments (playerId, userId, body) VALUES (?, ?, ?)");
    $stmt->bind_param("iis", $_GET['id'], $_COOKIE['userId'], $body);
    $stmt->execute() or die("Invalid query");
    $stmt->close();

    header("Location: list_players.php");
    exit();
}

# Show form
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments creator</title>
</head>
<body>
<header>
    <h1>Comments creator</h1>
</header>
<main class="player">
    <form action="#" method="post">
        <h3>Write your comment</h3>
        <textarea name="body"></textarea>
        <input type="submit" value="Send">
    </form>
    <form action="#" method="post" class="menu-form">
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>
```