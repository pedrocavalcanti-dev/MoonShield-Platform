(() => {
  "use strict";
  document.addEventListener("DOMContentLoaded", () => {
    const runtime=window.MoonShieldDevices;if(!runtime)return;const $=(id)=>document.getElementById(id),modal=$("devScanModal"),overlay=$("devScanOverlay"),list=$("devScanNetworks"),message=$("devScanMessage"),confirm=$("devScanConfirm");if(!modal||!overlay||!list||!confirm)return;
    const note=(value="",kind="")=>{message.textContent=value;message.className=`dev-scan-message${kind?` dev-scan-message--${kind}`:""}`;}; const close=()=>{modal.hidden=true;overlay.hidden=true;note();};
    const updateSelection = () => {
      list.querySelectorAll(".dev-scan-network").forEach((row) => {
        const input = row.querySelector("input"), status = row.querySelector(".dev-scan-network__status");
        if (status) status.textContent = input.disabled ? "Indisponível" : input.checked ? (list.dataset.scanning === "true" ? "Escaneando…" : "Selecionado") : "Não selecionado";
      });
    };
    const render = (networks) => {
      list.innerHTML = networks.length ? "" : '<p class="dev-no-data">Nenhuma rede disponível para scan.</p>';
      networks.forEach((network) => {
        const label = document.createElement("label"), allowed = Boolean(network.allowed);
        label.className = `dev-scan-network${allowed ? "" : " dev-scan-network--disabled"}`;
        label.innerHTML = `<input type="checkbox" value="${runtime.escapeHtml(network.id)}"${network.selected && allowed ? " checked" : ""}${allowed ? "" : " disabled"}>
          <span><span class="dev-scan-network__name"><i class="bi ${network.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3"}" aria-hidden="true"></i> ${runtime.escapeHtml(network.role || "Rede")}</span>
          <span class="dev-scan-network__meta">${runtime.escapeHtml(network.interface || "—")}<span>${runtime.escapeHtml(network.cidr || "—")}</span></span>
          <span class="dev-scan-network__note">${allowed ? `${Number(network.device_count || 0)} dispositivos` : "Não autorizada pela topologia"}</span>
          <span class="dev-scan-network__status"></span></span>`;
        list.appendChild(label);
      });
      updateSelection();
    };
    list.addEventListener("change", updateSelection);
    const open=async()=>{modal.hidden=false;overlay.hidden=false;note("Consultando redes monitoradas...","working");const networks=await runtime.loadNetworks();render(networks);note(networks.length?"":"Nenhuma rede autorizada foi retornada.");};
    const start=async()=>{const networks=Array.from(list.querySelectorAll("input:checked:not(:disabled)")).map((input)=>input.value);if(!networks.length){note("Selecione ao menos uma rede autorizada.","error");return;}confirm.disabled=true;list.dataset.scanning="true";updateSelection();note("Escaneando as redes selecionadas…","working");try{const response=await fetch(runtime.urls.scan,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRFToken":runtime.getCsrfToken()},body:JSON.stringify({networks})});const payload=await response.json();if(!response.ok||!payload.ok)throw new Error(payload.error||"O scan nao foi iniciado.");note("Atualizando inventario...","working");await runtime.refreshInventory();await runtime.loadNetworks();runtime.notify(`Scan concluido: ${Number(payload.found||0)} dispositivo(s) encontrado(s).`,"success");close();}catch(error){note(error.message||"Falha ao executar scan.","error");}finally{confirm.disabled=false;delete list.dataset.scanning;updateSelection();}};
    document.addEventListener("moonshield:scan:open",open);$("devScanClose")?.addEventListener("click",close);$("devScanCancel")?.addEventListener("click",close);overlay.addEventListener("click",close);confirm.addEventListener("click",start);
  });
})();
