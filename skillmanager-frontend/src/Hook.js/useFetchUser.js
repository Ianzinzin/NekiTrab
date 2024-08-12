// src/Hook.js/useFetchUser.js
import { useContext } from 'react';
import { buscarUsuarioId } from '../Pages/sevice/Usuario';
import { AuthContext } from '../components/Context/AuthorizarionCont';

function useFetchUser() {
    const { salvarUser } = useContext(AuthContext);
    
    const fetchUser = (userId) => {
        buscarUsuarioId(userId).then((res) => salvarUser(res.data));
    };

    return fetchUser;
}

export default useFetchUser; // Exportação padrão
