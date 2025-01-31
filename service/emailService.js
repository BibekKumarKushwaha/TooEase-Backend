
const nodemailer = require('nodemailer');
const sendEmail = async (options) => {
    if (!options.email || options.email.trim() === "") {
        console.error("Error: No recipient email provided!");
        return;
    }

    console.log("Attempting to send email to:", options.email); // Log recipient

    const transporter = nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: options.email,  // Ensure this is not empty
        subject: options.subject || "No Subject",
        text: options.message || "No Content",
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log("Email sent successfully:", info.response);
    } catch (error) {
        console.error("Error sending email:", error);
    }
};

module.exports = sendEmail;