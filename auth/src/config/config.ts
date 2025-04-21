export default () => ({
    jwt: {
        secret: process.env.JWT_SECRET,

    },
    database: {
        connectionString: process.env.MONGO_URI,
    },
    email: {    
        email: process.env.EMAIL,
    },
    password: {
        password: process.env.EMAIL_PASSWORD,
    },
});
