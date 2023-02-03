const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const bcrypto = require("bcrypto");

// Declare de schema of the Mongo model
var userSchema = new mongoose.Schema(
{
cofirstname: {
  type: String,
  required: true,
},
lastname: {
  type: String,
  required: true,
},
email: {
  type: String,
  required: true,
  unique: true,
},  
mobile: {
  type: String,
  required: true,
  unique: true,
}, 
password: {
  type: String,
  required: true,
},  
  role: {
    type: String,
    default: "user",
},
  isBlocked: {
    type: Boolean,
    default: false,
},
  cart: {
    type: Array,
    default: [],
},
address: [{ type: mongoose.Schema.ObjectId, ref: "Address" }],
wishlist: [{ type: mongoose.Schema.ObjectId, ref: "Product" }],
refreshToken: {
  type: String,
},
passwordChangedAt: Date,
passwordResetToken: String,
passwordResetExpires: Date,
},
{
  timestamps: true,
}
);

// Bcrypt the password
userSchema.pre("save", async function (next) {
  if(!this.isModified("Password")){
    next();
  }
  const salt = await bcrypt.genSaltSync(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});
// we have to match that password
userSchema.methods.isPasswordMatched = async function(enteredPassword) {
 return await bcrypt.compare(enteredPassword, this.password);
};
// Create password reset token
userSchema.methods.createPasswordResetToken = async function() {
  const resettoken = bcrypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto
  .createHash("sha256")
  .update(resettoken)
  .digest("hex");
  this.passwordResetExpires = Date.now() + 30 * 60 * 1000; // 10 minutes
  return resettoken;
};

// Export the model
module.exports = mongoose.model("User", userSchema);
