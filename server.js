require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const userRoute = require('./routes/user.route');
const errorHandler = require('./middlewares/error.middleware');

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(cors());

// Routes
app.use('/api/users', userRoute);

app.get('/', (req, res) => {
    res.send('Home Page');
});

// Error Handler
app.use(errorHandler);

const PORT = process.env.PORT || 4000;

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Database connected to ${PORT}`);
        })
    })
    .catch((err) => console.log(err));