<?php
// Inicia la sesión
session_start();

// Verifica si el usuario ya ha iniciado sesión, redirige a la página de inicio si es así
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: inicio.php");
    exit;
}

// Incluye la conexión a la base de datos
require_once "conexion.php";

// Define las variables e inicialízalas con valores vacíos
$username = $password = "";
$username_err = $password_err = "";

// Procesa los datos del formulario cuando se envía el formulario
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Verifica si el nombre de usuario está vacío
    if(empty(trim($_POST["username"]))){
        $username_err = "Por favor, ingresa tu nombre de usuario.";
    } else{
        $username = trim($_POST["username"]);
    }
    
    // Verifica si la contraseña está vacía
    if(empty(trim($_POST["password"]))){
        $password_err = "Por favor, ingresa tu contraseña.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Valida las credenciales
    if(empty($username_err) && empty($password_err)){
        $sql = "SELECT id, username, password FROM usuarios WHERE username = ?";
        
        if($stmt = $mysqli->prepare($sql)){
            $stmt->bind_param("s", $param_username);
            $param_username = $username;
            
            if($stmt->execute()){
                $stmt->store_result();
                
                // Verifica si el nombre de usuario existe, si es así, verifica la contraseña
                if($stmt->num_rows == 1){                    
                    $stmt->bind_result($id, $username, $hashed_password);
                    if($stmt->fetch()){
                        if(password_verify($password, $hashed_password)){
                            // Inicia la sesión
                            session_start();
                            
                            // Almacena datos en variables de sesión
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username;                            
                            
                            // Redirige al usuario a la página de inicio
                            header("location: inicio.php");
                        } else{
                            // Muestra un mensaje de error si la contraseña no es válida
                            $password_err = "La contraseña que has ingresado no es válida.";
                        }
                    }
                } else{
                    // Muestra un mensaje de error si el nombre de usuario no existe
                    $username_err = "No se encontró ninguna cuenta con ese nombre de usuario.";
                }
            } else{
                echo "Algo salió mal. Por favor, inténtalo de nuevo más tarde.";
            }

            // Cierra la declaración
            $stmt->close();
        }
    }
    
    // Cierra la conexión
    $mysqli->close();
}
?>
