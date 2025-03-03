const mongoose = require ('mongoose');

const postSchema = new mongoose.Schema ({
    title: {
        type: String,
        required: [true, "Title is required"],
        trim: true
    },
    description: {
        type: String,
        required: [true, "description is required"],
        trim: true,
       
    },
    userId:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
 }, {timestamps: true}
);

module.exports = mongoose.model('Post', postSchema);
