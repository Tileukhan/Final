const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const session = require('express-session');
const axios = require('axios');
require('dotenv').config();

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: 'auto' }
}));

let db;

async function connectToMongoDB() {
    try {
        const client = await MongoClient.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        db = client.db('BEBKA');
        console.log('Connected to MongoDB');
    } catch (error) {
        console.error('Could not connect to MongoDB:', error);
        process.exit(1);
    }
}

connectToMongoDB().then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

app.post('/register', async (req, res) => {
    const { username, password, email, firstName, lastName, age, country, gender } = req.body;

    try {
        const existingUser = await db.collection('Users').findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).send('Username or Email already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await db.collection('Users').insertOne({
            username,
            password: hashedPassword,
            email,
            firstName,
            lastName,
            age,
            country,
            gender,
            role: 'regular', // Default role is regular
            registeredAt: new Date(),
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Welcome to Our Service',
            text: `Hi ${firstName}, welcome to our service! We're excited to have you.`,
        };

        transporter.sendMail(mailOptions, (error) => {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).send('Error sending welcome email.');
            }
            res.redirect('/login.html');
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user.');
    }
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await db.collection('Users').findOne({ username });
        if (!user) {
            return res.status(400).send('User not found');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid credentials');
        }

        req.session.username = username;
        res.send('User logged in successfully');
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).send('Error logging in user.');
    }
});

function authorize(roles = []) {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return async (req, res, next) => {
        if (!req.session.username) {
            return res.status(401).send('Not authenticated');
        }

        try {
            const user = await db.collection('Users').findOne({ username: req.session.username });
            if (!user || !roles.includes(user.role)) {
                return res.status(403).send('Unauthorized');
            }

            next();
        } catch (error) {
            console.error('Authorization error:', error);
            res.status(500).send('Internal server error');
        }
    };
}

app.get('/admin', authorize('admin'), (req, res) => {
    res.send('Admin dashboard - Access Granted');
});
app.get('/api/stocks/:symbol', async (req, res) => {
    const symbol = req.params.symbol;
    const apiKey = process.env.ALPHA_VANTAGE_API_KEY; // Ensure this is set in your .env file
    const url = `https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol=${symbol}&apikey=${apiKey}`;

    try {
        const response = await axios.get(url);
        res.json(response.data['Time Series (Daily)']);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error fetching stock data');
    }
});



