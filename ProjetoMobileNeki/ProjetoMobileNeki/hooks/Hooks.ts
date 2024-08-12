import { useContext } from "react"
import { buscarUsuarioId } from "../service/usuario/usuario"
import { AuthContext } from "../context/authContext"

function useFetchUser(){
    const { user, salvarUser } = useContext(AuthContext)
    
    const fetchUser = (userId:number) =>{
    buscarUsuarioId(userId).then((res)=>salvarUser(res.data))
    }
    return fetchUser
}

export default useFetchUser;