import express from "express";
import { PrismaClient } from '@prisma/client';
import bcrypt from "bcrypt"; //cripitografar senha
import jwt from "jsonwebtoken" //token


//rotas publicas
const router=express.Router()
const prisma=new PrismaClient()
const JWTSECRET = process.env.JWTSECRET;

//rota de cadastro
router.post("/cadastro", async(req,res) => { 
    try{ 
        const cadastro = req.body //pega a resposta da requisição e guarda no cadastro

        //tamanho da criptografia
        const tamanho=await bcrypt.genSalt(10)
        const hashsenha=await bcrypt.hash(cadastro.password,tamanho) 
        //cadastra os dados do front no banco
        await prisma.user.create({
            data:{ 
                name:cadastro.name,
                email:cadastro.email,
                password :hashsenha
            }
        })
        res.status(201).json({message:"Usuário criado com sucesso!"})

    }catch(error) { 
        console.log("erro ao criar o usuário", error)
    }
     
    
})
//rota de login

router.post("/login", async(req,res) => {
    try{
        const login= req.body  //pega os dados do front e guarda no corpo da requisição
        const usuario = await prisma.user.findUnique({ 
            where:{ 
                email:login.email
            }
        })
        //verifica se tem usuario com o email igual no banco - se tem cadastro
        if (!usuario){
            return res.status(401).json ({Error: "Usuário não encontrado"})
        }
        //compara a senha do front com a do banco
        const senhaValida=await bcrypt.compare(login.password,usuario.password)
        if (!senhaValida){
            return res.status(401).json ({Error: "Senha inválida"})
        }
        //vai mascarar esses dados 
        const token = jwt.sign({id:usuario.id,name:usuario.name, email:usuario.email}, JWTSECRET,{ 
            expiresIn:"2h" //duração do token
        })


        res.status(200).json ({token})
    } catch(error ) { 
       // console.log("Erro ao realizar o login", error) 
        res.status(500).json({error:"Erro ao fazer o login"})
    }
    


})

export default router
