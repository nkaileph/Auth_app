const Joi = require('joi');

const signupSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

const signinSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
});

const acceptCodeSchema = Joi.object({
    email: Joi.string().email().required(),
    providedCode: Joi.string().required(),
});

const changePasswordSchema = Joi.object({
    oldPassword: Joi.string().required(),
    newPassword: Joi.string().min(6).required(),
});

const acceptFPCodeSchema = Joi.object({
    email: Joi.string().email().required(),
    providedCode: Joi.string().required(),
    newPassword: Joi.string().min(6).required(),
});

module.exports = {
    signupSchema,
    signinSchema,
    acceptCodeSchema,
    changePasswordSchema,
    acceptFPCodeSchema,
};