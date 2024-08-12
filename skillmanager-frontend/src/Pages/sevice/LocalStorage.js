export const recuperarItem = (campo) => {
    const itemRec = localStorage.getItem(campo);
    const itemProcessado = itemRec ? JSON.parse(itemRec) : '';
    return itemProcessado;
}
