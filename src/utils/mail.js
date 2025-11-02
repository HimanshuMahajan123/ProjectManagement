import Mailgen from "mailgen";
import nodemailer from "nodemailer";

// Generic email sending function
const sendEmail = async(options) => {
    const mailGenerator = new Mailgen({
        theme : "default",
        product : {
            name : "Project Management Tool",
            link : "https://projectmanagerlink.com/"
        }
    })

    const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent);
    const emailHTML = mailGenerator.generate(options.mailgenContent);

    const transporter = nodemailer.createTransport({
        host : process.env.MAILTRAP_SMTP_HOST,
        port : process.env.MAILTRAP_SMTP_PORT,
        auth : {
            user : process.env.MAILTRAP_SMTP_USER,
            pass : process.env.MAILTRAP_SMTP_PASSWORD
        }
    })

    const mail = {
        from : "mail.taskmanager@example.com",
        to : options.email,
        subject : options.subject,
        text : emailTextual,
        html : emailHTML
    }

    try {
        await transporter.sendMail(mail);
    } catch (error) {
        console.error("Error sending email: ", error);
    }
}

// Email verification mail content generator
const emailVerificationMailgenContent = (username , verificationUrl) => {
    return {
        body : {
            name : username,
            intro : "Welcome to our platform! We're excited to have you on board.",
            action : {
                instructions : "To get started, please verify your email address by clicking the button below:",
                button : {
                    color : "#22BC66",
                    text : "Verify your email",
                    link : verificationUrl
                }
            },
            outro : "If you did not create an account, no further action is required on your part."
        }
    }
}


// Forgot password mail content generator
const forgotPasswordMailgenContent = (username , passwordResetUrl) => {
    return {
        body : {
            name : username,
            intro : "We received a request to reset your password. Click the button below to proceed.",
            action : {
                instructions : "To reset your password, please click the button below:",
                button : {
                    color : "#FF5733",
                    text : "Reset Password",
                    link : passwordResetUrl
                }
            },
            outro : "If you did not request a password reset, please ignore this email."
        }
    }
}


export { emailVerificationMailgenContent , forgotPasswordMailgenContent , sendEmail };
