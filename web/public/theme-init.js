// Aplica a preferência de tema salva antes da primeira pintura, sem esperar o React.
// Sem valor salvo, o painel segue o sistema ("light dark"). Mantido mínimo de propósito.
try {
  var scheme = localStorage.getItem("vigiahost.color-scheme");
  if (scheme === "light" || scheme === "dark") {
    document.querySelector('meta[name="color-scheme"]').content = scheme;
  }
} catch {
  // Armazenamento bloqueado: segue o tema do sistema.
}
