import { api } from "./api";

export const loginApi = async (info) => {
    const url = "/auth/login";
    try {
        const response = await api.post(url, info);
        return response;
    } catch (error) {
        console.error("Erro ao fazer login:", error);
        throw error;
    }
}

export const cadastroApi = async (info) => {
    const url = "/usuarios/cadastrar";
    try {
        const response = await api.post(url, info);
        return response;
    } catch (error) {
        console.error("Erro ao cadastrar usuário:", error);
        throw error;
    }
}

export const removerSkill = async (info) => {
    const url = `/usuarios/${info.usuarioId}/removerskill/${info.skillId}`;
    try {
        const response = await api.delete(url);
        return response;
    } catch (error) {
        console.error("Erro ao remover skill:", error);
        throw error;
    }
}

export const buscarUsuarioId = async (id) => {
    const url = `/usuarios/${id}`;
    try {
        const response = await api.get(url);
        return response;
    } catch (error) {
        console.error("Erro ao buscar usuário por ID:", error);
        throw error;
    }
}

export const atualizarNivel = async (info) => {
    const url = `/usuarios/${info.usuarioId}/atualizarnivel`;
    try {
        const response = await api.put(url, info);
        return response;
    } catch (error) {
        console.error("Erro ao atualizar nível do usuário:", error);
        throw error;
    }
}

export const atribuirSkill = async (info) => {
    const url = `/usuarios/adicionarskill`;
    try {
        const response = await api.post(url, info);
        return response;
    } catch (error) {
        console.error("Erro ao atribuir skill ao usuário:", error);
        throw error;
    }
}
