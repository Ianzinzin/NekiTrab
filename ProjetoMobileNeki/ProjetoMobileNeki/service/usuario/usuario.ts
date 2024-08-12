import AsyncStorage from "@react-native-async-storage/async-storage";
import { atualizarNivelType, deleteSkillType, loginType } from "../../interfaces/TypesUsuario"
import { api } from "../api/api"

export const loginApi = async (info: loginType) => {
        const url = "/auth/login";
        const response = await api.post(url, info);
        return response;
    
}

export const cadastroApi = async (info:loginType) =>{
        const url = "/usuarios/cadastrar"
        const response = await api.post(url, info);
        return response
}

export const removerSkill = async (info:deleteSkillType) =>{    
        const url = `/usuarios/${info.usuarioId}/removerskill/${info.skillId}`
        const response = await api.delete(url, {
            headers: {
                'Authorization': `Bearer ${await AsyncStorage.getItem('token')}`
            }
        });
          return response
          
    }

export const atualizarNivel = async (info:atualizarNivelType) =>{
        const url = `/usuarios/${info.usuarioId}/atualizarnivel`
        const response = await api.put(url, info, {
            headers:{
                'Authorization': `Bearer ${await AsyncStorage.getItem('token')}`
            }
     })
     return response
    

}

export const atribuirSkill = async (info) =>{
        const url = `/usuarios/adicionarskill`
        const response = await api.post(url, info, {
            headers:{
                'Authorization': `Bearer ${await AsyncStorage.getItem('token')}`
            }
        })
        return response
}

export const buscarUsuarioId = async (id:number) =>{
        const url = `/usuarios/${id}`
        const response = await api.get(url, {headers:{
            'Authorization': `Bearer ${await AsyncStorage.getItem('token')}`
        }})
        return response
    }
    