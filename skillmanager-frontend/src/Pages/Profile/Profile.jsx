import './Profile.module.css';

export default function Profile() {
  return (
    <div className="profile-container">
      <h1>Perfil do Usuário</h1>
      <p>Email: usuario@example.com</p>
      <p>Skills:</p>
      <ul>
        <li>React</li>
        <li>JavaScript</li>
      </ul>
    </div>
  );
}
