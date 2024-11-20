<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';  
$app = new \Slim\App();  

// User Register
$app->post('/users/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = password_hash($data->password, PASSWORD_BCRYPT);  

    $servername = "localhost";
    $username = "root";
    $password = " ";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        // set the PDO error mode to exception
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

      
        $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':username', $usr);
        $stmt->bindParam(':password', $pass);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    } catch (PDOException $e) {
        // Send error response
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

// User Authentication with Token Rotation
$app->post('/user/authenticate', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the user exists
        $sql = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':username', $usr);
        $stmt->execute();
        $user = $stmt->fetch();

        // Verify password
        if ($user && password_verify($pass, $user['password'])) {
            // Token generation
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'https://library.org',
                'aud' => 'https://library.org',
                'iat' => $iat,
                'exp' => $iat + 3600,  // Token expiration (1 hour)
                "data" => [
                    "userid" => $user['userid']
                ]
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            // Return token and refresh token
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $jwt)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Authentication Failed"))));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

// Token Refresh Endpoint
$app->post('/user/refresh-token', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = $data->token;

    $key = 'server_hack';

    try {
        // Decode the token
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        
        // Generate a new token with the same user ID
        $iat = time();
        $payload = [
            'iss' => 'https://library.org',
            'aud' => 'https://library.org',
            'iat' => $iat,
            'exp' => $iat + 3600,  // Token expiration (1 hour)
            "data" => [
                "userid" => $decoded->data->userid
            ]
        ];
        $newJwt = JWT::encode($payload, $key, 'HS256');

        // Return the new token
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newJwt)));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token"))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

//  User Update
$app->put('/user/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = $data->token;
    $newUsername = $data->username;
    $newPassword = password_hash($data->password, PASSWORD_BCRYPT);  

    $key = 'server_hack';

    try {
        // Decode the token
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        // User ID from the token
        $userId = $decoded->data->userid;

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        // Update user data
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE users SET username = :username, password = :password WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':username', $newUsername);
        $stmt->bindParam(':password', $newPassword);
        $stmt->bindParam(':userid', $userId);

        $stmt->execute();

        // Generate a new token after successful update
        $iat = time();
        $payload = [
            'iss' => 'https://library.org',
            'aud' => 'https://library.org',
            'iat' => $iat,
            'exp' => $iat + 3600,  // Token expiration (1 hour)
            "data" => [
                "userid" => $userId
            ]
        ];
        $newJwt = JWT::encode($payload, $key, 'HS256');

        // Return success response with new token
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newJwt)));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token or " . $e->getMessage()))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

// Add Book
$app->post('/books/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $title = $data->title;
    $authors = $data->authors; // Get authors from request body
    $token = $data->token;

    $key = 'server_hack';

    try {
        // Decode the token to get user information
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        // Insert the new book into the database
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Use prepared statements to avoid SQL injection
        $sql = "INSERT INTO books (title, authors) VALUES (:title, :authors)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':authors', $authors);
        $stmt->execute();

        // Return success response
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book added successfully.")));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token or " . $e->getMessage()))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

// Update Book
$app->put('/books/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = $data->token;
    $bookId = $data->bookid; // Book ID to update
    $newTitle = $data->title; // New title
    $newAuthors = $data->authors; // New authors

    $key = 'server_hack';

    try {
        // Decode the token to get user information
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        // Update the book in the database
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books SET title = :title, authors = :authors WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $newTitle);
        $stmt->bindParam(':authors', $newAuthors);
        $stmt->bindParam(':bookid', $bookId);

        $stmt->execute();

        // Return success response
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book updated successfully.")));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token or " . $e->getMessage()))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

// Delete Book
$app->delete('/books/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = $data->token;
    $bookId = $data->bookid; // Book ID to delete

    $key = 'server_hack';

    try {
        // Decode the token to get user information
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        // Delete the book from the database
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM books WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();

        // Return success response
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book deleted successfully.")));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token or " . $e->getMessage()))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

// Book List
$app->get('/books/list', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Select all books from the books table
        $stmt = $conn->query("SELECT * FROM books");
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Return the books in JSON format
        $response->getBody()->write(json_encode(array("status" => "success", "data" => $books)));
    } catch (PDOException $e) {
        // Return error response
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

$app->run();