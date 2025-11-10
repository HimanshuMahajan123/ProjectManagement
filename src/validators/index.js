import { body } from "express-validator";

const userRegistrationValidator = () => {
    return [
        body("email")
            .trim()
            .notEmpty().withMessage("Email is required")
            .isEmail().withMessage("Invalid email format"),

        body("username")
            .trim()
            .notEmpty().withMessage("Username is required")
            .isLowercase().withMessage("Username must be in lowercase")
            .isLength({ min: 3, max: 20 }).withMessage("Username must be between 3 and 20 characters"),

        body("password")
            .trim()
            .notEmpty().withMessage("Password is required"),

        body("fullname")
            .optional()
            .trim()
            .isLength({ min: 2, max: 100 }).withMessage("Full name must be between 2 and 100 characters")
    ]
}

const userLoginValidator = () => {
    return [
        body("email")
            .notEmpty()
            .withMessage("email is required")
            .isEmail()
            .withMessage("Email is invalid"),

        body("password")
            .notEmpty()
            .withMessage("password is required")
    ]
}   

const userChangeCurrentPasswordValidator = () => {
    return [
        body("currentPassword")
            .notEmpty()
            .withMessage("Current password is required"),

        body("newPassword")
            .notEmpty()
            .withMessage("New password is required")
    ]
}

const userForgotPasswordValidator = () => {
    return [
        body("email")
            .notEmpty()
            .withMessage("Email is required")
            .isEmail()
            .withMessage("Email is invalid")
    ]
}

const userResetForgottenPasswordValidator = () => {
    return [
        body("newPassword")
            .notEmpty()
            .withMessage("New password is required")
    ]
}

export {
    userRegistrationValidator,
    userLoginValidator,
    userChangeCurrentPasswordValidator,
    userForgotPasswordValidator,
    userResetForgottenPasswordValidator
}