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
        // 1. Obtener el id máximo actual
        db.query('SELECT MAX(id) AS maxId FROM usuarios', async (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).send({ success: false, message: 'Error al obtener ID' });
            }

            const nextId = (results[0].maxId ?? 0) + 1;


            // 2. Hashear contraseña
            const hash = await bcrypt.hash(contrasena, 10);

            // 3. Insertar usuario con ID calculado
            db.query(
                'INSERT INTO usuarios (id, nombre, fecha_nacimiento, correo, contrasena) VALUES (?, ?, ?, ?, ?)',
                [nextId, nombre, fechaNacimiento, correo, hash],
                (err2, result) => {
                    if (err2) {
                        console.error(err2);
                        return res.status(500).send({ success: false, message: 'Error al registrar' });
                    }
                    res.send({ success: true, message: 'Usuario registrado correctamente' });
                }
            );
        });

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


app.get('/buscar-numero', (req, res) => {
    const numero = req.query.numero;

    if (!numero) {
        return res.status(400).json({ success: false, message: 'Falta el número' });
    }

    db.query(
        'SELECT * FROM numeros_reportados WHERE numero_telefono = ?',
        [numero],
        (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ success: false, message: 'Error en la base de datos' });
            }

            if (results.length === 0) {
                return res.status(404).json({ success: false, message: 'Número no encontrado' });
            }

            res.json({ success: true, datos: results[0] });
        }
    );
});

app.post('/reportar', (req, res) => {
    const { numero_telefono, tipo_telefono, ubicacion, descripcion } = req.body;

    if (!numero_telefono || !tipo_telefono || !ubicacion || !descripcion) {
        return res.status(400).json({ success: false, message: 'Faltan datos' });
    }

    // Verificamos si el número ya existe
    db.query('SELECT * FROM numeros_reportados WHERE numero_telefono = ?', [numero_telefono], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Error al consultar la base de datos' });
        }

        if (results.length > 0) {
            // Ya existe → solo sumamos 1 a numero_reportes
            const id = results[0].id;
            const reportesActuales = results[0].numero_reportes ?? 0;

            db.query(
                'UPDATE telefonos SET numero_reportes = ? WHERE id = ?',
                [reportesActuales + 1, id],
                (err2, result2) => {
                    if (err2) {
                        console.error(err2);
                        return res.status(500).json({ success: false, message: 'Error al actualizar número' });
                    }
                    return res.json({ success: true, message: 'Número actualizado (reporte sumado)' });
                }
            );
        } else {
            // No existe → calculamos nuevo ID manualmente y lo insertamos
            db.query('SELECT MAX(id) AS maxId FROM numeros_reportados', (err3, results3) => {
                if (err3) {
                    console.error(err3);
                    return res.status(500).json({ success: false, message: 'Error al generar nuevo ID' });
                }

                const nextId = (results3[0].maxId ?? 0) + 1;

                db.query(
                    'INSERT INTO numeros_reportados (id, numero_telefono, tipo_telefono, ubicacion, descripcion, numero_reportes) VALUES (?, ?, ?, ?, ?, ?)',
                    [nextId, numero_telefono, tipo_telefono, ubicacion, descripcion, 1],
                    (err4, result4) => {
                        if (err4) {
                            console.error(err4);
                            return res.status(500).json({ success: false, message: 'Error al insertar nuevo número' });
                        }

                        res.json({ success: true, message: 'Número reportado con éxito' });
                    }
                );
            });
        }
    });
});



app.listen(10000, () => {
    console.log('Servidor corriendo en puerto 10000');
});
