const API_BASE = "/api";

let featureNames = [];

let predictionCount = 0;

let predictionHistory = [];


// ======================================
// INITIALIZATION
// ======================================

document.addEventListener("DOMContentLoaded", async () => {

    await checkBackend();

    await loadFeatures();

    setupEventListeners();

});


// ======================================
// BACKEND HEALTH
// ======================================

async function checkBackend() {

    const connectionText =
        document.getElementById("connection-text");

    const sidebarStatus =
        document.getElementById("sidebar-status");

    try {

        const response = await fetch(
            `${API_BASE}/health`
        );

        const data = await response.json();

        if (!response.ok) {

            throw new Error(data.message || "Backend unavailable.");

        }

        connectionText.textContent = "API Connected";

        sidebarStatus.textContent = "Operational";

        document.getElementById("model-status").textContent =
            "ONLINE";

        document.getElementById("model-name").textContent =
            data.model;

        document.getElementById("feature-count").textContent =
            data.features;

        showToast("Backend connected successfully.");

    } catch (error) {

        connectionText.textContent = "API Offline";

        sidebarStatus.textContent = "Disconnected";

        document.getElementById("model-status").textContent =
            "OFFLINE";

        showToast("Unable to connect to Flask backend.");

        console.error(error);

    }

}


// ======================================
// FEATURE LOADING
// ======================================

async function loadFeatures() {

    const container =
        document.getElementById("feature-container");

    const status =
        document.getElementById("loaded-feature-status");

    try {

        const response = await fetch(
            `${API_BASE}/features`
        );

        const data = await response.json();

        if (!response.ok || !data.success) {

            throw new Error(
                data.error || "Unable to retrieve features."
            );

        }

        featureNames = data.features;

        if (
            !Array.isArray(featureNames) ||
            featureNames.length !== data.total_features
        ) {

            throw new Error("Invalid feature definition returned by API.");

        }

        document.getElementById("feature-count").textContent =
            featureNames.length;

        status.textContent =
            `${featureNames.length} model features loaded successfully`;

        renderFeatureGroups();

        document.getElementById("analyze-button").disabled =
            false;

    } catch (error) {

        container.innerHTML = `
            <div class="loading-message">
                Failed to load model features.
                Please check the Flask backend.
            </div>
        `;

        status.textContent = "Feature loading failed.";

        console.error(error);

        showToast(error.message);

    }

}


// ======================================
// FEATURE GROUPING
// ======================================

function getFeatureGroup(feature) {

    const name = feature.toLowerCase();

    if (
        name.includes("flow") ||
        name.includes("port") ||
        name.includes("protocol")
    ) {

        return "Flow Information";

    }

    if (
        name.includes("fwd") &&
        (
            name.includes("packet") ||
            name.includes("segment") ||
            name.includes("bulk") ||
            name.includes("header")
        )
    ) {

        return "Forward Traffic Statistics";

    }

    if (
        name.includes("bwd") &&
        (
            name.includes("packet") ||
            name.includes("segment") ||
            name.includes("bulk") ||
            name.includes("header")
        )
    ) {

        return "Backward Traffic Statistics";

    }

    if (
        name.includes("length") ||
        name.includes("len") ||
        name.includes("iat")
    ) {

        return "Packet Length and Timing Statistics";

    }

    if (
        name.includes("flag") ||
        name.includes("psh") ||
        name.includes("urg") ||
        name.includes("syn") ||
        name.includes("ack") ||
        name.includes("rst") ||
        name.includes("fin")
    ) {

        return "TCP Flags";

    }

    if (
        name.includes("active") ||
        name.includes("idle")
    ) {

        return "Active and Idle Statistics";

    }

    if (
        name.includes("subflow")
    ) {

        return "Subflow Statistics";

    }

    return "Additional Network Statistics";

}


// ======================================
// RENDER FEATURE FORM
// ======================================

function renderFeatureGroups() {

    const container =
        document.getElementById("feature-container");

    container.innerHTML = "";

    const groups = {};

    featureNames.forEach(feature => {

        const group = getFeatureGroup(feature);

        if (!groups[group]) {

            groups[group] = [];

        }

        groups[group].push(feature);

    });


    Object.entries(groups).forEach(
        ([groupName, features], index) => {

            const groupElement =
                document.createElement("div");

            groupElement.className = "feature-group";

            if (index !== 0) {

                groupElement.classList.add("collapsed");

            }

            const header = document.createElement("button");

            header.type = "button";

            header.className = "feature-group-header";

            header.innerHTML = `
                <div>
                    <h3>${escapeHTML(groupName)}</h3>
                    <span>${features.length} features</span>
                </div>

                <span class="arrow">▼</span>
            `;

            header.addEventListener("click", () => {

                groupElement.classList.toggle("collapsed");

            });


            const content =
                document.createElement("div");

            content.className = "feature-group-content";


            features.forEach(feature => {

                const field =
                    document.createElement("div");

                field.className = "input-group";

                const label =
                    document.createElement("label");

                label.textContent = feature;

                label.htmlFor = `feature-${feature}`;

                const input =
                    document.createElement("input");

                input.type = "number";

                input.step = "any";

                input.required = true;

                input.autocomplete = "off";

                input.id = `feature-${feature}`;

                input.dataset.feature = feature;

                input.placeholder = "Enter numeric value";

                input.addEventListener("input", () => {

                    input.classList.remove("invalid");

                });

                field.appendChild(label);

                field.appendChild(input);

                content.appendChild(field);

            });


            groupElement.appendChild(header);

            groupElement.appendChild(content);

            container.appendChild(groupElement);

        }

    );

}


// ======================================
// FORM EVENT LISTENERS
// ======================================

function setupEventListeners() {

    document
        .getElementById("prediction-form")
        .addEventListener("submit", handlePrediction);


    document
        .getElementById("fill-zero-button")
        .addEventListener("click", fillWithZeros);


    document
        .getElementById("clear-button")
        .addEventListener("click", clearForm);


    document
        .getElementById("clear-history-button")
        .addEventListener("click", clearHistory);

}


// ======================================
// GET USER INPUT
// ======================================

function collectInputData() {

    const inputData = {};

    const inputs = document.querySelectorAll(
        "[data-feature]"
    );

    let invalid = false;

    inputs.forEach(input => {

        const feature = input.dataset.feature;

        const value = input.value.trim();

        if (value === "") {

            input.classList.add("invalid");

            invalid = true;

            return;

        }

        const numericValue = Number(value);

        if (!Number.isFinite(numericValue)) {

            input.classList.add("invalid");

            invalid = true;

            return;

        }

        input.classList.remove("invalid");

        inputData[feature] = numericValue;

    });


    if (invalid) {

        throw new Error(
            "Please enter valid numeric values for all 78 features."
        );

    }

    if (
        Object.keys(inputData).length !== featureNames.length
    ) {

        throw new Error(
            "Input feature count does not match the model."
        );

    }

    return inputData;

}


// ======================================
// SEND PREDICTION TO FLASK
// ======================================

async function handlePrediction(event) {

    event.preventDefault();

    const button =
        document.getElementById("analyze-button");

    const originalContent = button.innerHTML;

    try {

        const inputData = collectInputData();

        button.disabled = true;

        button.innerHTML = "Analyzing traffic...";

        const response = await fetch(
            `${API_BASE}/predict`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(inputData)
            }
        );


        const data = await response.json();

        if (!response.ok || !data.success) {

            throw new Error(
                data.error || "Prediction request failed."
            );

        }

        displayPrediction(data.result);

        addToHistory(data.result);

        predictionCount++;

        document.getElementById("prediction-count").textContent =
            predictionCount;

        document
            .getElementById("result-section")
            .classList.remove("hidden");

        document
            .getElementById("result-section")
            .scrollIntoView({
                behavior: "smooth"
            });

        showToast("Prediction completed successfully.");

    } catch (error) {

        showToast(error.message);

        console.error(error);

    } finally {

        button.disabled = false;

        button.innerHTML = originalContent;

    }

}


// ======================================
// DISPLAY PREDICTION
// ======================================

function displayPrediction(result) {

    const prediction = result.prediction;

    const confidence = result.confidence;

    const probabilities = result.probabilities;

    const isDdos = prediction === "DDoS";

    const mainCard =
        document.getElementById("result-main-card");

    mainCard.classList.toggle("danger", isDdos);


    document.getElementById("result-symbol").textContent =
        isDdos ? "!" : "✓";


    document.getElementById("prediction-label").textContent =
        prediction.toUpperCase();


    document.getElementById("prediction-description").textContent =
        isDdos
            ? "Potential DDoS attack detected by the machine learning model."
            : "The submitted network traffic was classified as benign.";


    const confidencePercent =
        confidence * 100;

    document.getElementById("confidence-value").textContent =
        `${confidencePercent.toFixed(2)}%`;

    document.getElementById("confidence-bar").style.width =
        `${confidencePercent}%`;


    const benign =
        (probabilities["BENIGN"] || 0) * 100;

    const ddos =
        (probabilities["DDoS"] || 0) * 100;


    document.getElementById("benign-probability").textContent =
        `${benign.toFixed(2)}%`;

    document.getElementById("ddos-probability").textContent =
        `${ddos.toFixed(2)}%`;


    document.getElementById("benign-bar").style.width =
        `${benign}%`;

    document.getElementById("ddos-bar").style.width =
        `${ddos}%`;

}


// ======================================
// PREDICTION HISTORY
// ======================================

function addToHistory(result) {

    const now = new Date();

    const entry = {

        time: now.toLocaleTimeString(),

        prediction: result.prediction,

        confidence: result.confidence

    };

    predictionHistory.unshift(entry);

    renderHistory();

}


function renderHistory() {

    const tbody =
        document.getElementById("history-body");

    tbody.innerHTML = "";

    if (predictionHistory.length === 0) {

        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="empty-history">
                    No predictions yet.
                </td>
            </tr>
        `;

        return;

    }


    predictionHistory.forEach(item => {

        const isDdos =
            item.prediction === "DDoS";

        const row = document.createElement("tr");

        const timeCell = document.createElement("td");

        timeCell.textContent = item.time;

        const predictionCell = document.createElement("td");

        const predictionBadge = document.createElement("span");

        predictionBadge.className =
            `badge ${isDdos ? "badge-ddos" : "badge-benign"}`;

        predictionBadge.textContent =
            item.prediction;

        predictionCell.appendChild(predictionBadge);


        const confidenceCell = document.createElement("td");

        confidenceCell.textContent =
            `${(item.confidence * 100).toFixed(2)}%`;


        const statusCell = document.createElement("td");

        statusCell.textContent =
            isDdos ? "Potential Threat" : "Normal Traffic";


        row.appendChild(timeCell);

        row.appendChild(predictionCell);

        row.appendChild(confidenceCell);

        row.appendChild(statusCell);

        tbody.appendChild(row);

    });

}


// ======================================
// FORM UTILITIES
// ======================================

function fillWithZeros() {

    const inputs = document.querySelectorAll(
        "[data-feature]"
    );

    inputs.forEach(input => {

        input.value = "0";

        input.classList.remove("invalid");

    });

    showToast(
        "All features filled with zero. This is a test shortcut, not realistic traffic data."
    );

}


function clearForm() {

    document
        .getElementById("prediction-form")
        .reset();

    document.querySelectorAll(
        "[data-feature]"
    ).forEach(input => {

        input.classList.remove("invalid");

    });

    showToast("Input form cleared.");

}


function clearHistory() {

    predictionHistory = [];

    renderHistory();

    showToast("Prediction history cleared.");

}


// ======================================
// UTILITIES
// ======================================

function escapeHTML(value) {

    return String(value).replace(
        /[&<>"']/g,
        character => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;"
        })[character]
    );

}


let toastTimeout;

function showToast(message) {

    const toast =
        document.getElementById("toast");

    toast.textContent = message;

    toast.classList.add("show");

    clearTimeout(toastTimeout);

    toastTimeout = setTimeout(() => {

        toast.classList.remove("show");

    }, 3500);

}