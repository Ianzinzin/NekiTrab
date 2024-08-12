import React from 'react';

// src/hooks/ExceptionHook.js
export const ExceptHook = (exception) => {
    const split = exception.response.data.split(':');
    const mensagem = split[2];
    return mensagem;
};
