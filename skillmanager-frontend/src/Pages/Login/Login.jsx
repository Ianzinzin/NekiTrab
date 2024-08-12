import React, { useContext } from 'react'
import styles from './Login.module.css'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faEye, faUser } from '@fortawesome/free-solid-svg-icons'
import { loginApi } from '../../Pages/sevice/Usuario'
import { AuthContext } from '../../components/Context/AuthorizarionCont'
import { Link, useNavigate } from 'react-router-dom'
import { ToastContainer } from 'react-toastify'

export const Login = () => {
  const { salvarUser } = useContext(AuthContext)
  const navigate = useNavigate()
  const [mostrarSenha, setMostrarSenha] = React.useState(false)
  const [estadoSenha, setEstadoSenha] = React.useState('password')
  const [userInfo, setUserInfo] = React.useState({
    email: '',
    senha: ''
  })

  const handleChange = (event) => {
    const { name, value } = event.target
    setUserInfo({ ...userInfo, [name]: value })
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    try {
      const res = await loginApi(userInfo)
      salvarUser(res.data.usuario)
      localStorage.setItem('token', res.data.token)
      navigate('/home')
    } catch (err) {
      // Removido tratamento de erro
    }
  }

  const handleSenhaVisivel = () => {
    setMostrarSenha(!mostrarSenha)
    setEstadoSenha(mostrarSenha ? 'password' : 'text')
  }

  return (
    <div className={styles.container}>
      <div className={styles.wrapper}>
        <form onSubmit={handleLogin}>
          <h1>Login</h1>
          <div className={styles.inputBox}>
            <input name='email' value={userInfo.email} onChange={handleChange} type='email' placeholder='Email' required />
            <FontAwesomeIcon className={styles.icone} icon={faUser} />
          </div>
          <div className={styles.inputBox}>
            <input name='senha' value={userInfo.senha} onChange={handleChange} type={estadoSenha} placeholder='Senha' required />
            <FontAwesomeIcon className={styles.iconeSenha} onClick={handleSenhaVisivel} icon={faEye} />
          </div>
          <button type='submit'>Login</button>
          <div className={styles.linkRegistro}>
            <p>Não tem uma conta? <Link to='/registro'>Cadastrar-se</Link></p>
          </div>
        </form>
      </div>
      <ToastContainer />
    </div>
  )
}
