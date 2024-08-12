import { NativeStackNavigationProp } from "@react-navigation/native-stack";

export interface loginType{
    email: string,
    senha: string
}

export interface UsuarioType{
    id: number,
    email: string,
    role:string,
    skills:[]
}

export interface senhaRecType{
    senha:string ,
    salvar:boolean
}

export interface deleteSkillType{
    usuarioId: number,
    skillId:number
}

export interface atualizarNivelType extends deleteSkillType{
    nivel:number
}

export type RootStackParamList = {
    Login: undefined;
    Cadastro: undefined;
    Home: undefined;
};

export type CadastroScreenNavigationProp = NativeStackNavigationProp<RootStackParamList,'Cadastro'>;
export type LoginScreenNavigationProp = NativeStackNavigationProp<RootStackParamList,'Login'>;