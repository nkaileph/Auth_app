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

const createPostSchema = Joi.object({
	title: Joi.string().min(3).max(60).required(),
	description: Joi.string().min(3).max(600).required(),
	userId: Joi.string().required(),
});

module.exports = {
    signupSchema,
    signinSchema,
    acceptCodeSchema,
    changePasswordSchema,
    acceptFPCodeSchema,
    createPostSchema
};

