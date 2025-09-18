import express from "express"
import { PrismaClient } from '@prisma/client';
import bcriypt from "bcrypt"

const router=express.Router()
const prisma=new PrismaClient()

router.post("/cadastro", async(req,res) => { 
    try{ 
        const cadastro = req.body //pega a resposta da requisição e guarda no cadastro

        const tamanho=await bcriypt.genSalt(10)
        const hashsenha=await bcriypt.hash(cadastro.senha,tamanho)
        await prisma.user.create({
            data:{ 

                name:cadastro.nome,
                email:cadastro.email,
                senha:hashsenha

            }
        })
        res.status(2001).json

    }catch(error) { 
        console.log("erro ao criar o usuário", error)
    }
     
    
})
export default router
