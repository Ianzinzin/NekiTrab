import { api } from "./api";

export const listarTodasSkills = async () => {
    const url = "/skills";
    try {
        const response = await api.get(url);
        return response;
    } catch (error) {
        console.error("Erro ao listar todas as skills:", error);
        throw error;
    }
}

export const cadastrarSkill = async (info, file) => {
    const url = "/skills/cadastrar";
    const formData = new FormData();
    formData.append('skill', new Blob([JSON.stringify(info)], { type: 'application/json' }));
    formData.append("file", file);
    try {
        const response = await api.post(url, formData, {
            headers: {
                'Content-Type': 'multipart/form-data'
            }
        });
        return response;
    } catch (error) {
        console.error("Erro ao cadastrar skill:", error);
        throw error;
    }
}
