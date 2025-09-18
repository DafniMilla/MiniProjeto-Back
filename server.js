import express from 'express'
import publicRouter from "./routes/public.js"

const app=express()
app.use(express.json())


app.use('/',publicRouter)
app.listen(8000,() => console.log("servidor rodando na porta 8000") )