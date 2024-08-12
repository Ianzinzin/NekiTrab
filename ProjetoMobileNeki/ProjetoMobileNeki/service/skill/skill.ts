import AsyncStorage from "@react-native-async-storage/async-storage";
import { api } from "../api/api";

export const listarTodasSkills = async () =>{
    const url = "/skills"
    const response = await api.get(url, {headers:{
        'Authorization': 'Bearer ' + await AsyncStorage.getItem('token')
    }})
    
    return response
}

export const cadastrarSkill = async (info,file) =>{
    const url = "/skills/cadastrar"
    const formData = new FormData()
    formData.append('skill', new Blob([JSON.stringify(info)], {type: 'application/json'}))
    formData.append("file", file);
    const response = api.post(url,formData, {headers: {
        'Authorization': 'Bearer ' + await AsyncStorage.getItem('token'),
        'Content-Type': 'multipart/form-data'
    }})
    return response
}