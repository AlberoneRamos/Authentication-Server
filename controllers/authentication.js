const JWT = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
    const timestamp = new Date().getTime()
    return JWT.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(request,response,next){
    response.send({token:tokenForUser(request.user)});
}

exports.signup = function (request, response, next) {
    const email = request.body.email;
    const password = request.body.password;

    if (!email || !password) {
        return response.status(422).send({ error: 'Email e senha são obrigatórios.' });
    }

    // Verificar se existe um usuário com o mesmo e-mail
    User.findOne({ email: email }, function (error, existingUser) {
        if (error) {
            return next(error);
        }
        // Se sim, retornar um erro
        if (existingUser) {
            return response.status(422).send({ error: 'E-mail em uso.' });
        }
        // Caso contrário, criar e salvar o usuário
        const user = new User({
            email: email,
            password: password
        });
        user.save(function (error) {
            if (error) {
                return next(error);
            }
        });
        // Response
        response.json({ token: tokenForUser(user) });
    });



};