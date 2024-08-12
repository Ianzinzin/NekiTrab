import React, { useContext } from 'react';
import { BrowserRouter, Route, Routes, Navigate } from 'react-router-dom';
import { Login } from '../Pages/Login/Login.jsx';
import { CadastroPage } from '../Pages/Register/Register.jsx';
import { HomePage } from '../Pages/Home/Home.jsx';
import { AuthContext } from '../components/Context/AuthorizarionCont.jsx';

export const Rotas = () => {
    const { user } = useContext(AuthContext);

  return (
    <BrowserRouter>
      <Routes>
        {/* Rotas acessíveis apenas para usuários autenticados */}
        {user && user.role ? (
          <>
            <Route path="/" element={<Navigate to="/home" />} />
            <Route path="/home" element={<HomePage />} />
            <Route path="/registro" element={<Navigate to="/home" />} />
            <Route path="*" element={<Navigate to="/home" />} />
          </>
        ) : (
          <>
            {/* Rotas acessíveis para usuários não autenticados */}
            <Route path="/" element={<Login />} />
            <Route path="/login" element={<Login />} />
            <Route path="/registro" element={<CadastroPage />} />
            <Route path="*" element={<Navigate to="/" />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  );
};
