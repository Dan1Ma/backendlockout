const express = require('express');
const mysql = require('mysql2');
const dbUrl = process.env.MYSQL_URL;
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// 🔐 Cambia estos datos por los de tu base de datos MySQL (en la nube o local)
const db = mysql.createConnection(dbUrl);
// Ruta para registrar usuario
app.post('/registro', async (req, res) => {
    const { nombre, correo, fechaNacimiento, contrasena } = req.body;

    if (!nombre || !correo || !fechaNacimiento || !contrasena) {
        return res.status(400).send({ success: false, message: 'Faltan datos' });
    }

    try {
        // Cifrar la contraseña con bcrypt
        const hash = await bcrypt.hash(contrasena, 10);

        db.query(
            'INSERT INTO usuarios (nombre, fecha_nacimiento, correo, contrasena) VALUES (?, ?, ?, ?)',
            [nombre, fechaNacimiento, correo, hash],
            (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send({ success: false, message: 'Error al registrar' });
                }
                res.send({ success: true, message: 'Usuario registrado correctamente' });
            }
        );
    } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: 'Error al procesar la solicitud' });
    }
});

// Ruta para iniciar sesión
app.post('/login', (req, res) => {
    const { nombre, contrasena } = req.body;

    if (!nombre || !contrasena) {
        return res.status(400).send({ success: false, message: 'Faltan datos' });
    }

    db.query('SELECT * FROM usuarios WHERE nombre = ?', [nombre], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send({ success: false, message: 'Error en la base de datos' });
        }

        if (results.length === 0) {
            return res.status(401).send({ success: false, message: 'Usuario no encontrado' });
        }

        const usuario = results[0];

        const coincide = await bcrypt.compare(contrasena, usuario.contrasena);

        if (coincide) {
            res.send({ success: true, message: 'Inicio de sesión exitoso' });
        } else {
            res.status(401).send({ success: false, message: 'Contraseña incorrecta' });
        }
    });
});


app.listen(10000, () => {
    console.log('Servidor corriendo en puerto 10000');
});
