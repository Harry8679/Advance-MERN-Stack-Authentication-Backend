const nodemailer = require('nodemailer');;
const hbs = require('nodemailer-express-handlebars');
const path = require('path');

const sendMail = async(subject, send_to, sent_from, reply_to, template, name, link) => {
    // Create Email Transport
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: 587,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    const handlearOptions = {
        viewEngine: {
            extName: '.handlebars',
            partialDir: path.resolve('./views'),
            defaultLayout: false
        },
        viewPath: path.resolve('./views'),
        extName: '.handlebars',
    };

    transporter.use('compile', hbs(handlearOptions));

    // Options for sending email
    const options = { 
        from: sent_from, to: send_to, reply_to: reply_to, subject, template,
        context: { name, link }
    }

    // Send Email
    transporter.sendMail(options, function (err, info) {
        if (err) {
            console.log(err);
        } else {
            console.log(info);
        }
    });
}

module.exports = sendMail;