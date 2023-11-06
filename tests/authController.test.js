const request = require('supertest')
const { User } = require('../database/models')
const db = require('../database/models')
const axios = require('axios')
const nodemailer = require('nodemailer')
const bcrypt = require('bcrypt')
const app = require('../src/app')

// Simulação de envio de email
jest.mock('nodemailer', () => ({
  createTransport: () => ({
    sendMail: (options, callback) => {
      callback(null)
    }
  })
}))

jest.mock('axios')

// Definindo um mock da função axios.get para simular a resposta da API
axios.get.mockImplementation(url => {
  if (url.includes('zerobounce')) {
    // Simulando uma resposta da API ZeroBounce
    return Promise.resolve({
      data: { status: 'valid' } // Modifique isso para atender aos seus casos de teste
    })
  }
  // Se não for uma solicitação para a API ZeroBounce, deixe o Axios funcionar normalmente
  return axios.get(url)
})


describe('Testes de autenticação', () => {
  beforeAll(async () => {
    await db.sequelize.sync({ force: true })
  })

  afterEach(async () => {
    // Limpe o banco de dados após a execução de cada teste
    await User.destroy({ truncate: true })
  })

  it('Deve registrar um usuário com sucesso', async () => {
    const response = await request(app).post('/auth/register').send({
      username: 'testuser',
      email: 'carlossoarespedro20@gmail.com',
      password: 'password123'
    })

    expect(response.status).toBe(201)
    expect(response.body).toEqual({
      message: 'Código de confirmação enviado por e-mail'
    })

    const user = await User.findOne({
      where: { email: 'carlossoarespedro20@gmail.com' }
    })
    expect(user).toBeTruthy()
  })

  it('Deve retornar erro ao não fornecer campos obrigatórios', async () => {
    const response = await request(app).post('/auth/register').send({})

    expect(response.status).toBe(400)
    expect(response.body.message).toBe('Username, email, and password are required')
  })

  it('Deve retornar erro se o e-mail já existe no banco de dados', async () => {
    // Registre um usuário com o mesmo e-mail antes do teste
    await User.create({
      username: 'existinguser',
      email: 'carlossoarespedro20@gmail.com',
      password: 'password123',
      confirmationCode: '1234',
      isConfirmed: false
    })

    const response = await request(app).post('/auth/register').send({
      username: 'testuser',
      email: 'carlossoarespedro20@gmail.com',
      password: 'password123'
    })

    expect(response.status).toBe(200)
    expect(response.body.exists).toBe(true)
    expect(response.body.message).toBe('O email já possui uma conta.')
  })

  it('Deve retornar erro se o email não é válido', async () => {
    // Simulando uma resposta da API ZeroBounce com um email inválido
    axios.get.mockResolvedValue({ data: { status: 'invalid' } })

    const response = await request(app).post('/auth/register').send({
      username: 'testuser',
      email: 'invalid_email@example.com',
      password: 'password123'
    })

    expect(response.status).toBe(400)
    expect(response.body.message).toBe('O email não é válido')
  })
})

describe('Testes para o controlador "verify"', () => {
  beforeEach(async () => {
    // Antes de cada teste, limpe o banco de dados
    await User.destroy({ where: {} })
  })

  it('Deve verificar o usuário com sucesso quando os campos são fornecidos corretamente', async () => {
    // Crie um usuário com um código de confirmação válido no banco de dados
    const user = await User.create({
      email: 'example@example.com',
      confirmationCode: '12345'
    })

    const response = await request(app)
      .post('/auth/verify')
      .send({ email: 'example@example.com', confirmationCode: '12345' })

    expect(response.status).toBe(200)
    expect(response.text).toContain('Registro concluído com sucesso.')

    // Verifique se o usuário foi confirmado no banco de dados
    const confirmedUser = await User.findOne({
      where: { email: 'example@example.com' }
    })
    expect(confirmedUser.isConfirmed).toBe(true)
    expect(confirmedUser.confirmationCode).toBeNull()
  })

  it('Deve retornar um erro quando campos estão faltando', async () => {
    const response = await request(app).post('/auth/verify').send({})

    expect(response.status).toBe(400)
    expect(response.body.message).toBe(
      'Email and confirmation code are required'
    )
  })

  it('Deve retornar um erro quando o código de confirmação não é válido', async () => {
    const response = await request(app)
      .post('/auth/verify')
      .send({ email: 'example@example.com', confirmationCode: 'invalidCode' })

    expect(response.status).toBe(400)
    expect(response.body.message).toBe('Código de confirmação inválido')
  })

  it('Deve retornar um erro quando o email não está associado a um código de confirmação válido', async () => {
    const response = await request(app)
      .post('/auth/verify')
      .send({ email: 'nonexistent@example.com', confirmationCode: '12345' })

    expect(response.status).toBe(400)
    expect(response.body.message).toBe('Código de confirmação inválido')
  })
})

describe('Testes para o controlador "login"', () => {
  beforeEach(async () => {
    // Antes de cada teste, limpe o banco de dados
    await User.destroy({ where: {} })
  })

  it('Deve fazer login com sucesso com credenciais válidas', async () => {
    // Crie um usuário no banco de dados
    const hashedPassword = await bcrypt.hash('password123', 10)
    const user = await User.create({
      email: 'example@example.com',
      password: hashedPassword,
      isConfirmed: true // Simulando uma conta confirmada
    })

    const response = await request(app)
      .post('/auth/login')
      .send({ email: 'example@example.com', password: 'password123' })

    expect(response.status).toBe(200)
    expect(response.text).toContain('Login bem-sucedido')
  })

  it('Deve retornar um erro ao não fornecer campos obrigatórios', async () => {
    const response = await request(app).post('/auth/login').send({})

    expect(response.status).toBe(400)
    expect(response.text).toBe('Email and password are required')
  })

  it('Deve retornar um erro quando o email não existe no banco de dados', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({ email: 'nonexistent@example.com', password: 'password123' })

    expect(response.status).toBe(401)
    expect(response.text).toBe('Email inválido.')
  })

  it('Deve retornar um erro quando a conta não está confirmada', async () => {
    const hashedPassword = await bcrypt.hash('password123', 10)
    const user = await User.create({
      email: 'example@example.com',
      password: hashedPassword,
      isConfirmed: false // Simulando uma conta não confirmada
    })

    const response = await request(app)
      .post('/auth/login')
      .send({ email: 'example@example.com', password: 'password123' })

    expect(response.status).toBe(401)
    expect(response.text).toBe(
      'Sua conta ainda não foi confirmada. Verifique seu email e confirme sua conta.'
    )
  })

  it('Deve retornar um erro de credenciais inválidas (senha incorreta)', async () => {
    const hashedPassword = await bcrypt.hash('password123', 10)
    const user = await User.create({
      email: 'example@example.com',
      password: hashedPassword,
      isConfirmed: true
    })

    const response = await request(app)
      .post('/auth/login')
      .send({ email: 'example@example.com', password: 'wrongPassword' })

    expect(response.status).toBe(401)
    expect(response.text).toBe('Credenciais inválidas')
  })

  it('Deve retornar um erro ao verificar a senha (por exemplo, exceção)', async () => {
    // Crie um usuário com uma senha hash inválida
    const user = await User.create({
      email: 'example@example.com',
      password: 'invalidPasswordHash', // Senha inválida
      isConfirmed: true
    })

    const response = await request(app)
      .post('/auth/login')
      .send({ email: 'example@example.com', password: 'password123' })

    expect(response.status).toBe(401)
    expect(response.text).toBe('Credenciais inválidas')
  })
})