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
            .isLength({ min: 3 , max: 20 }).withMessage("Username must be between 3 and 20 characters"),

        body("password")
            .trim()
            .notEmpty().withMessage("Password is required"),

        body("fullname")
            .optional()
            .trim()
            .isLength({ min: 2, max: 100 }).withMessage("Full name must be between 2 and 100 characters")
    ]
}

export {
    userRegistrationValidator
}