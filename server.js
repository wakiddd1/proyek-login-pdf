const express = require('express');
const path = require('path');
const session = require('express-session');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

const db = mysql.createConnection({
    host: process.env.MYSQLHOST,     // Nama variabel dari Railway
    user: process.env.MYSQLUSER,     // Nama variabel dari Railway
    password: process.env.MYSQLPASSWORD, // Nama variabel dari Railway
    database: process.env.MYSQLDATABASE, // Nama variabel dari Railway
    port: process.env.MYSQLPORT,         // Nama variabel dari Railway
    // PlanetScale memerlukan SSL, tapi Railway biasanya tidak saat koneksi internal
    // jadi kita hapus bagian ssl
});

// Melakukan koneksi ke database
db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Successfully connected to the database.');
});

// Atur EJS sebagai view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'kunci-rahasia-jangan-disebar',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Middleware untuk memeriksa otentikasi
const checkAuth = (req, res, next) => {
    if (req.session.loggedin) {
        next();
    } else {
        res.redirect('/');
    }
};

// --- ROUTES ---

// Route untuk menampilkan halaman login
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views/login.html'));
});

// Route untuk menampilkan halaman registrasi
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views/register.html'));
});

// Route untuk memproses data REGISTRASI
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Blok validasi untuk memastikan input tidak kosong
    if (!username || !password || username.trim() === '' || password.trim() === '') {
        return res.status(400).render('error', {
            title: "Registrasi Gagal",
            errorMessage: "Pastikan username dan password sudah terisi dengan benar."
        });
    }

    const hashedPassword = await bcrypt.hash(password, 8);

    db.query('INSERT INTO users SET ?', { username: username, password: hashedPassword }, (err, result) => {
        if (err) {
            console.error(err);
            return res.send('Gagal mendaftar, username mungkin sudah digunakan.');
        }
        console.log('User registered:', username);
        res.redirect('/');
    });
});

// Route untuk memproses data LOGIN
// Route untuk memproses data LOGIN
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Blok validasi untuk login
    if (!username || !password || username.trim() === '' || password.trim() === '') {
        return res.status(400).render('error', {
            title: "Login Gagal",
            errorMessage: "Username dan password tidak boleh kosong untuk login."
        });
    }

    // Lanjutkan proses cek ke database
    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;

        if (results.length > 0 && await bcrypt.compare(password, results[0].password)) {
            req.session.loggedin = true;
            req.session.user = results[0];
            res.redirect('/dashboard');
        } else {
            // Jika username atau password salah, kirim ke halaman error
            return res.status(401).render('error', {
                title: "Login Gagal",
                errorMessage: "Kombinasi username dan password yang Anda masukkan salah."
            });
        }
    });
});

// Route untuk halaman DASHBOARD yang dilindungi
app.get('/dashboard', checkAuth, (req, res) => {
    const pdfFileName = req.session.user.pdf_file;
    const userName = req.session.user.username;
    res.render('dashboard', { pdfFile: pdfFileName, username: userName });
});

// Route untuk proses LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return console.log(err);
        res.redirect('/');
    });
});

// Route KHUSUS untuk menampilkan PDF
app.get('/view-pdf/:filename', (req, res) => {
    const { filename } = req.params;
    const filePath = path.join(__dirname, 'public', 'pdf', filename);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="' + filename + '"');

    res.sendFile(filePath, (err) => {
        if (err) {
            console.log(err);
            res.status(404).send('File tidak ditemukan');
        }
    });
});

// Menjalankan server
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});

// Final deploy untuk Railway
