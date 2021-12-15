import { inject, injectable } from 'tsyringe';
import { IUsersRepository } from '../../repositories/IUsersRepository';
import { sign } from 'jsonwebtoken'
import { compareSync } from 'bcrypt'
import { AppError } from '../../../../errors/AppError';

interface IRequest {
    email: string;
    password: string;
}
interface IResponse {
    user: {
        name: string,
        email: string
    },
    token: string
}

@injectable()
class AuthenticateUserUseCase {
    constructor(
        @inject('UsersRepository') 
        private usersRepository: IUsersRepository 
    ) {}

    async execute({ email, password }: IRequest): Promise<IResponse> {
        //Usuario existe
        const user =await this.usersRepository.findByEmail(email)
        if(!user) {
            throw new AppError("Email or password incorrect!")
        }
        //Senha esta correta
        const passwordMatch = await compareSync(password, user.password)
        if(!passwordMatch) {
            throw new AppError("Email or password incorrect!")
        }
        //Gerar jsonwebtoken
        //ignitenode
        const token = sign({}, "2b4d11d41c70f49571fba155f652f151", {
            subject: user.id,
            expiresIn: "1d"
        })
        const tokenReturn: IResponse = {
            token,
            user: {
                name: user.name,
                email: user.email
            }
        }
        return tokenReturn
    }
}

export { AuthenticateUserUseCase }