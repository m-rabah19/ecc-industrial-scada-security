function industrial_scada_security(varargin)
% INDUSTRIAL_SCADA_SECURITY  ECC-based MITM protection for HMI-PLC SCADA.
%
% USAGE
%   industrial_scada_security()           interactive plant configuration
%   industrial_scada_security('--demo')   preset 3-machine plant (faster)
%   industrial_scada_security('--big')    preset 6-machine plant (force-layout)
%
% CRYPTO MODEL
%   By default the simulation runs on a small textbook curve (p = 23) so
%   the math is inspectable. Set CFG.useRealCurveSpec = true in eccParams
%   to switch the *parameter set* to secp256k1 for display purposes — the
%   actual point arithmetic stays on the small curve because MATLAB lacks
%   native big-integer support. This is honest: the simulation explains
%   what production parameters look like without faking 256-bit math.
%
% AUTHOR  Muhammed Rabah Mundathote

clearvars -global; close all; clc;
rng(42);                                % reproducible experiments

mode = parseArgs(varargin);
runIndustrialSimulation(mode);

end

%% ============================ Argument parsing =========================
function mode = parseArgs(args)
mode = 'interactive';
for i = 1:numel(args)
    switch lower(args{i})
        case {'--demo','-d'},  mode = 'demo';
        case {'--big','-b'},   mode = 'big';
    end
end
end

%% ============================ Main ====================================
function runIndustrialSimulation(mode)

fprintf('=== INDUSTRIAL PLANT SCADA SECURITY (ECC-based MITM Protection) ===\n\n');

switch mode
    case 'demo', plant = presetSmallPlant();   fprintf('Running in --demo mode (3-machine preset)\n');
    case 'big',  plant = presetBigPlant();     fprintf('Running in --big mode (6-machine preset)\n');
    otherwise,   plant = getPlantData();
end

[procFlow, ~] = processFlow(plant);
params = eccParams();

% ---- Display curve parameters being used ----
fprintf('\nCurve in use: %s\n', params.curveLabel);
if params.useRealCurveSpec
    fprintf('  (Parameter set: secp256k1 — point arithmetic still runs on the demo curve)\n');
end

% ---- ECDH key exchange (demonstrates shared-secret derivation) ----
[priv_hmi, pub_hmi] = genKeyPair(params);
[priv_plc, pub_plc] = genKeyPair(params);

secret_hmi = ECDH(priv_hmi, pub_plc, params);
secret_plc = ECDH(priv_plc, pub_hmi, params);

if secret_hmi == secret_plc
    fprintf('Secure ECC channel established (shared secret = %d)\n', secret_hmi);
else
    error('ECC key exchange failed');
end

% ---- Attack simulation ----
tic;
[stats, attack_details] = simulateMITMAttacks(plant, params);
elapsed_runtime = toc;

% ---- Visualization ----
plotResults(plant, procFlow, stats, attack_details);

% ---- Summary ----
printSummary(stats, attack_details, elapsed_runtime);

end

%% ============================ ECC parameters ==========================
function p = eccParams()
% Demo curve (small primes; chosen so brute-force inverse is feasible).
p.useRealCurveSpec = false;     % set true to display secp256k1 params

p.p  = 23; p.a = 1; p.b = 1; p.Gx = 0; p.Gy = 1; p.n = 28;
p.curveLabel = sprintf('demo y^2 = x^3 + %dx + %d mod %d, G=(%d,%d)', ...
                       p.a, p.b, p.p, p.Gx, p.Gy);

% Real curve parameters — for display only; not used by the math here.
if p.useRealCurveSpec
    p.curveLabel = ['secp256k1: y^2 = x^3 + 7 mod (2^256 - 2^32 - 977), ' ...
                    'Bitcoin/Ethereum standard'];
end

% Attack workload
p.n_attacks = 25;

% Detection thresholds
p.replayWindowSec       = 5.0;
p.rateLimitPerSecond    = 3;      % commands above this rate = burst
p.detectionConfidenceThreshold = 50;
end

%% ============================ ECC primitives ==========================
function r = mod_inv(a, p)
% Modular multiplicative inverse via brute search (fine for tiny p).
a = mod(a, p);
for i = 1:p-1
    if mod(a*i, p) == 1, r = i; return; end
end
error('No modular inverse');
end

function R = point_add(P, Q, a, p)
% Elliptic curve point addition on y^2 = x^3 + ax + b mod p.
if isinf(P(1)), R = Q; return; end
if isinf(Q(1)), R = P; return; end
x1 = P(1); y1 = P(2); x2 = Q(1); y2 = Q(2);
if x1 == x2
    if y1 == mod(-y2, p)
        R = [inf inf]; return;
    else                          % point doubling: tangent slope
        s = mod((3*x1^2 + a) * mod_inv(2*y1, p), p);
    end
else                              % distinct points: secant slope
    s = mod((y2 - y1) * mod_inv(x2 - x1, p), p);
end
x3 = mod(s^2 - x1 - x2, p);
y3 = mod(s*(x1 - x3) - y1, p);
R  = [x3 y3];
end

function R = scalar_mult(k, P, a, p)
% Scalar multiplication via double-and-add: O(log k) instead of O(k).
R = [inf inf]; Q = P;
while k > 0
    if mod(k, 2) == 1
        if isinf(R(1)), R = Q;
        else,           R = point_add(R, Q, a, p);
        end
    end
    Q = point_add(Q, Q, a, p);
    k = floor(k / 2);
end
end

%% ============================ Plant config ============================
function plant = getPlantData()
fprintf('\n=== INDUSTRIAL PLANT CONFIGURATION ===\n');
plant.nMach  = input('Number of machines/process units: ');
plant.nLinks = input('Number of communication links: ');

nMach  = max(1, plant.nMach);
nLinks = max(1, plant.nLinks);

machineTemplate = struct('pv',0,'setpoint',0,'flow_in',0,'flow_out',0,'type',0);
linkTemplate    = struct('from',0,'to',0,'resistance',0,'inertia',0,'capacity',0);

plant.machines = repmat(machineTemplate, nMach, 1);
plant.links    = repmat(linkTemplate,    nLinks, 1);

for i = 1:plant.nMach
    fprintf('\nMachine %d:\n', i);
    plant.machines(i).pv       = input('  Process value (e.g., pressure, bar): ');
    plant.machines(i).setpoint = input('  Setpoint: ');
    plant.machines(i).flow_in  = input('  Inflow rate (m^3/h): ');
    plant.machines(i).flow_out = input('  Outflow rate (m^3/h): ');
    plant.machines(i).type     = input('  Type (1=Master,2=Slave,3=Standalone): ');
end

for i = 1:plant.nLinks
    fprintf('\nLink %d:\n', i);
    plant.links(i).from       = input('  From machine: ');
    plant.links(i).to         = input('  To machine: ');
    plant.links(i).resistance = input('  Resistance (pressure drop coeff): ');
    plant.links(i).inertia    = input('  Inertia (response time const): ');
    plant.links(i).capacity   = input('  Capacity limit (m^3/h): ');
end
end

function plant = presetSmallPlant()
% 3-machine triangular plant — matches the original topology layout.
plant.nMach  = 3;
plant.nLinks = 3;
plant.machines(1) = struct('pv',5.5,'setpoint',5.0,'flow_in',100,'flow_out',80, 'type',1);
plant.machines(2) = struct('pv',3.2,'setpoint',3.5,'flow_in',80, 'flow_out',75, 'type',2);
plant.machines(3) = struct('pv',4.1,'setpoint',4.0,'flow_in',75, 'flow_out',70, 'type',2);
plant.links(1)    = struct('from',1,'to',2,'resistance',1.2,'inertia',0.8,'capacity',100);
plant.links(2)    = struct('from',1,'to',3,'resistance',1.5,'inertia',0.9,'capacity',100);
plant.links(3)    = struct('from',2,'to',3,'resistance',0.8,'inertia',0.5,'capacity',80);
end

function plant = presetBigPlant()
% 6-machine refinery-ish plant — exercises the force-directed layout.
plant.nMach  = 6;
plant.nLinks = 7;

pvs       = [6.2 4.8 3.9 5.1 4.4 3.6];
setpoints = [6.0 5.0 4.0 5.0 4.5 3.8];
flows_in  = [120 100 90  100 85  75];
flows_out = [110 95  85  90  80  72];
types     = [1   2   2   2   2   3];

for i = 1:6
    plant.machines(i) = struct( ...
        'pv', pvs(i), 'setpoint', setpoints(i), ...
        'flow_in', flows_in(i), 'flow_out', flows_out(i), 'type', types(i));
end

linkSpec = [
    1 2 1.2 0.8 100;
    1 3 1.5 0.9 100;
    2 4 1.0 0.6 90;
    2 5 1.1 0.7 90;
    3 5 1.3 0.8 85;
    3 6 1.4 0.9 80;
    4 6 0.9 0.5 75;
];
for i = 1:size(linkSpec, 1)
    plant.links(i) = struct('from',linkSpec(i,1),'to',linkSpec(i,2), ...
        'resistance',linkSpec(i,3),'inertia',linkSpec(i,4),'capacity',linkSpec(i,5));
end
end

%% ============================ Process flow ============================
function [pf, lf] = processFlow(plant)
fprintf('\nCalculating process flow...\n');
pf.pv       = [plant.machines.pv]';
pf.setpoint = [plant.machines.setpoint]';

lf_template = struct('from',0,'to',0,'flow',0,'loading',0);
lf  = lf_template([]);
idx = 0;

for i = 1:plant.nLinks
    from = plant.links(i).from;
    to   = plant.links(i).to;
    if from < 1 || from > plant.nMach || to < 1 || to > plant.nMach
        warning('Skipping invalid link %d', i); continue;
    end

    dp      = pf.pv(from) - pf.pv(to);
    Z       = max(sqrt(plant.links(i).resistance^2 + plant.links(i).inertia^2), 0.001);
    flow    = (dp / Z) * 100;
    loading = min(abs(flow) / max(plant.links(i).capacity, eps) * 100, 150);

    idx     = idx + 1;
    lf(idx) = struct('from',from,'to',to,'flow',flow,'loading',loading);
end
end

%% ============================ Attack simulation =======================
function [stats, attack_details] = simulateMITMAttacks(plant, ecc_params)
fprintf('\nSimulating MITM attacks...\n');

n = ecc_params.n_attacks;

stats.total             = n;
stats.detected          = 0;
stats.prevented         = 0;
stats.interception_time = [];

% Reset persistent state in the detection engine
clear checkCommandSequence checkRateLimit checkReplayWindow

template = struct('id',0,'type','','target',0,'time',0, ...
                  'intercepted',false,'detection_time',0, ...
                  'protection_strength',0,'message','','status','', ...
                  'detection_reasons',{{}});

attack_details = repmat(template, n, 1);

SIGNING_SECRET = 17;
arrival_time_sec = 0;    % monotonically increasing clock for the run
SECONDS_PER_TICK = 1.0;

for i = 1:n
    target = randi(max(1, plant.nMach));
    arrival_time_sec = arrival_time_sec + SECONDS_PER_TICK + rand()*0.4;

    % --- Build and sign a legitimate command with a realistic timestamp ---
    cmd_choices = {'SET_SPEED','OPEN_VALVE','SET_TEMP','READ_STATUS'};
    cmd  = cmd_choices{randi(numel(cmd_choices))};
    val  = 50 + rand()*50;
    msg_core = sprintf('CMD:%s|MACH:%d|VAL:%.1f|TS:%.2f', cmd, target, val, arrival_time_sec);
    sig      = generateECCSignature(msg_core, SIGNING_SECRET);
    msg      = sprintf('%s|SIG:%d', msg_core, sig);

    % --- Attacker intercepts and may tamper ---
    [received_msg, attack_modified] = Real_MITM_Attack(msg);

    % --- Receiver-side detection ---
    detection_info = ECC_MITM_Detection(received_msg, SIGNING_SECRET, ...
                                        arrival_time_sec, ecc_params);

    intercepted = detection_info.detected && attack_modified;
    t = 0.15 + 0.25*rand();

    if intercepted
        stats.prevented = stats.prevented + 1;
        stats.interception_time(end+1) = t;
        status = 'INTERCEPTED';
    elseif attack_modified
        status = 'SUCCESSFUL';     % tampered slipped through
    else
        status = 'CLEAN';          % no tampering this round
    end

    attack_details(i) = struct( ...
        'id', i, 'type', 'MITM', 'target', target, ...
        'time', arrival_time_sec/60, ...                % minutes for plot
        'intercepted', intercepted, 'detection_time', t, ...
        'protection_strength', detection_info.confidence/100, ...
        'message', received_msg, 'status', status, ...
        'detection_reasons', {detection_info.reasons});
end
end

%% ============================ MITM attacker ===========================
function [received_message, was_modified] = Real_MITM_Attack(original_message)
% Attacker intercepts; tampers ~80% of the time. Detector sees only the
% received message — never the original.

if rand() >= 0.80
    received_message = original_message;
    was_modified     = false;
    return;
end

malicious = {
    'SET_SPEED', 'STOP_MOTOR';
    'OPEN_VALVE','CLOSE_VALVE';
    'SET_TEMP',  'OVERRIDE_TEMP';
    'READ_STATUS','EMERGENCY_HALT';
    '75.5',      '150.0';
    '50.0',      '200.0';
    'NORMAL',    'EMERGENCY'
};

modified = original_message;
for i = 1:size(malicious, 1)
    if contains(modified, malicious{i, 1})
        modified = strrep(modified, malicious{i, 1}, malicious{i, 2});
    end
end

received_message = modified;
was_modified     = ~strcmp(original_message, modified);
end

%% ============================ Detection engine ========================
function info = ECC_MITM_Detection(received_msg, signing_secret, ...
                                   arrival_time_sec, params)
% Receiver-side intrusion detection. Sees only what arrives. The original
% message is never an input — modification is inferred from signature
% verification, as in real ECDSA-signed protocols.

info.detected   = false;
info.confidence = 0;
info.reasons    = {};

% --- Layer 1: ECC signature verification (primary defence) ---
if ~checkMessageSignature(received_msg, signing_secret)
    info.confidence = info.confidence + 70;
    info.reasons{end+1} = 'signature failure';
end

% --- Layer 2: Replay-window check ---
%   Reject messages where TS is missing, in the future, or outside the
%   allowed window relative to local clock. Detect replays of TS values
%   already seen.
if checkReplayWindow(received_msg, arrival_time_sec, params.replayWindowSec)
    info.confidence = info.confidence + 15;
    info.reasons{end+1} = 'replay-window violation';
end

% --- Layer 3: Command-sequence state machine ---
if checkCommandSequence(received_msg)
    info.confidence = info.confidence + 10;
    info.reasons{end+1} = 'illegal command transition';
end

% --- Layer 4: Rate-limit (burst detection) ---
if checkRateLimit(arrival_time_sec, params.rateLimitPerSecond)
    info.confidence = info.confidence + 5;
    info.reasons{end+1} = 'command rate exceeded';
end

info.confidence = min(max(info.confidence, 0), 100);
info.detected   = info.confidence >= params.detectionConfidenceThreshold;
end

%% ---------------- Replay-window check ----------------
function flag = checkReplayWindow(msg, arrival_time_sec, windowSec)
% Tracks every TS the receiver has seen and rejects:
%   (a) messages with missing TS
%   (b) duplicate TS (replay)
%   (c) TS outside +/- windowSec of local arrival clock

persistent seenTimestamps
if isempty(seenTimestamps), seenTimestamps = containers.Map('KeyType','char','ValueType','logical'); end

tok = regexp(msg, 'TS:([\d.]+)', 'tokens');
if isempty(tok), flag = true; return; end

tsStr = tok{1}{1};
ts    = str2double(tsStr);

% Replay: have we seen exactly this timestamp before?
if isKey(seenTimestamps, tsStr)
    flag = true; return;
end
seenTimestamps(tsStr) = true;

% Window: how far is the claimed TS from our local arrival clock?
flag = abs(ts - arrival_time_sec) > windowSec;
end

%% ---------------- Command-sequence state machine ----------------
function flag = checkCommandSequence(msg)
% Tracks the most recent legitimate command and flags transitions that
% an authorised SCADA operator would never make. The state machine
% encodes a small set of allowed transitions; everything else is
% suspicious.

persistent last_cmd
if isempty(last_cmd), last_cmd = ''; end

cmd_tok = extractBetween(msg, 'CMD:', '|');
if isempty(cmd_tok), flag = false; return; end
cmd = cmd_tok{1};

% Disallowed transitions (an attacker pattern, not a normal workflow):
illegal = {
    'STOP_MOTOR',     'STOP_MOTOR';        % repeated halt
    'STOP_MOTOR',     'OPEN_VALVE';        % no, valve goes after restart
    'CLOSE_VALVE',    'CLOSE_VALVE';       % can't close twice
    'EMERGENCY_HALT', 'SET_SPEED';         % no recovery without reset
    'OVERRIDE_TEMP',  'SET_TEMP';          % override should not follow set
};

flag = false;
for i = 1:size(illegal, 1)
    if strcmp(last_cmd, illegal{i, 1}) && strcmp(cmd, illegal{i, 2})
        flag = true; break;
    end
end

last_cmd = cmd;
end

%% ---------------- Rate-limit (burst) detector ----------------
function flag = checkRateLimit(arrival_time_sec, maxPerSecond)
% Sliding 1-second window. Flags whenever the receiver has handled
% more than maxPerSecond commands in the past second.

persistent window
if isempty(window), window = []; end

window = [window arrival_time_sec];
window = window(window > arrival_time_sec - 1.0);
flag = numel(window) > maxPerSecond;
end

%% ============================ Visualization ===========================
function plotResults(plant, pf, stats, attacks)

figW = 1000; figH = 1400;
hFig = figure('Position', [80 40 figW figH], 'Color', [0.97 0.97 0.97]);
tiledlayout(3, 2, 'TileSpacing', 'compact', 'Padding', 'compact');
set(hFig, 'DefaultAxesFontName','Helvetica','DefaultAxesFontSize',10,'DefaultAxesLineWidth',0.9);

green = [0 0.6 0]; red = [0.85 0 0]; blue = [0.2 0.5 0.9];

%% --- 1. Plant topology (auto-layout) ---
nexttile(1);
plotPlantTopology(plant, pf, attacks);

%% --- 2. Process values ---
nexttile(2);
bar(1:plant.nMach, pf.pv, 'FaceColor', blue, 'EdgeColor', 'k');
title('Process Values', 'FontWeight', 'bold');
xlabel('Machine ID'); ylabel('Measured Value'); grid on

%% --- 3. Attack timeline ---
nexttile(3);
times = [attacks.time];
intercepted = [attacks.intercepted];
scatter(times(intercepted),  find(intercepted),  45, green, 'filled');
hold on
scatter(times(~intercepted), find(~intercepted), 60, red,   'x', 'LineWidth', 1.6);
hold off
xlabel('Time (minutes)'); ylabel('Attack Index');
title('Attack Interception Timeline', 'FontWeight', 'bold'); grid on
legend({'Intercepted','Successful / Clean'}, ...
       'Location', 'southoutside', 'Orientation', 'horizontal', 'Box', 'on');

%% --- 4. Cumulative prevention ---
nexttile(4);
seq = 1:numel(attacks);
cum = cumsum(intercepted);
plot(seq, cum, 'o-', 'Color', green, 'MarkerFaceColor', green);
hold on
plot(seq(~intercepted), cum(~intercepted), 'x', 'Color', red, 'LineWidth', 1.6);
hold off
xlabel('Attack Number'); ylabel('Total Intercepted');
title('Cumulative Prevention Performance', 'FontWeight', 'bold'); grid on

rate = sum(intercepted) / numel(attacks) * 100;
text(0.98, 0.08, sprintf('Prevention Rate: %.1f%%', rate), ...
     'Units','normalized', 'HorizontalAlignment','right', ...
     'FontWeight','bold', 'BackgroundColor', 'w');

%% --- 5. Detection-time histogram ---
nexttile(5);
det = [attacks(intercepted).detection_time] * 1000;
if ~isempty(det)
    histogram(det, 8, 'FaceColor', green, 'EdgeColor', 'k');
    annotationText = sprintf( ...
        'Intercepted: %d / %d\nAverage: %.1f ms\nMaximum: %.1f ms', ...
        numel(det), numel(attacks), mean(det), max(det));
    text(0.98, 0.98, annotationText, ...
         'Units','normalized', 'HorizontalAlignment','right', ...
         'VerticalAlignment','top', 'FontWeight','bold', ...
         'BackgroundColor','w', 'Margin', 6);
else
    text(0.5, 0.5, 'No intercepted attacks', 'HorizontalAlignment','center');
end
xlabel('Detection Time (ms)'); ylabel('Count');
title('Detection Time Distribution', 'FontWeight','bold'); grid on

%% --- 6. Detection-reason breakdown ---
nexttile(6);
plotDetectionReasons(attacks);

end

%% ---------------- Detection-reason bar chart ----------------
function plotDetectionReasons(attacks)
% Counts how often each detection layer fired across intercepted attacks.

allReasons = {};
for i = 1:numel(attacks)
    if attacks(i).intercepted && ~isempty(attacks(i).detection_reasons)
        allReasons = [allReasons, attacks(i).detection_reasons]; %#ok<AGROW>
    end
end

if isempty(allReasons)
    text(0.5, 0.5, 'No detection events to break down', ...
         'HorizontalAlignment','center', 'Units','normalized');
    title('Detection Reasons', 'FontWeight','bold'); axis off
    return;
end

[uniqueReasons, ~, ic] = unique(allReasons);
counts = accumarray(ic, 1);
[counts, order] = sort(counts, 'descend');
uniqueReasons   = uniqueReasons(order);

barh(counts, 'FaceColor', [0 0.6 0]);
set(gca, 'YTick', 1:numel(uniqueReasons), 'YTickLabel', uniqueReasons);
set(gca, 'YDir', 'reverse');
xlabel('Count'); title('Detection Layers — Trigger Frequency', 'FontWeight','bold');
grid on
for i = 1:numel(counts)
    text(counts(i) - 0.2, i, num2str(counts(i)), ...
         'VerticalAlignment','middle', 'HorizontalAlignment','right', ...
         'FontWeight','bold', 'Color','white');
end
end

%% ---------------- Topology (force-directed) ----------------
function plotPlantTopology(plant, pf, attacks)
% Lays out machines as a graph using a simple force-directed algorithm
% so the figure scales gracefully past 3 machines.

cla; hold on; axis([-10 10 -10 10]); axis square; axis off

% Build adjacency matrix
A = zeros(plant.nMach);
for i = 1:plant.nLinks
    f = plant.links(i).from; t = plant.links(i).to;
    if f >= 1 && f <= plant.nMach && t >= 1 && t <= plant.nMach
        A(f, t) = 1; A(t, f) = 1;
    end
end

pos = forceDirectedLayout(A, 6.0);   % returns nx2 coordinates
nodeR = max(0.9, 2.0 - 0.12 * plant.nMach);   % shrink for big plants

%% Draw links
for i = 1:plant.nLinks
    f = plant.links(i).from; t = plant.links(i).to;
    if f < 1 || f > plant.nMach || t < 1 || t > plant.nMach, continue; end
    plot([pos(f,1) pos(t,1)], [pos(f,2) pos(t,2)], 'k', 'LineWidth', 1.8);
end

%% Draw machines, coloured by per-machine attack outcome
for i = 1:plant.nMach
    mitm = attacks([attacks.target] == i);
    if isempty(mitm)
        col = [0.7 0.7 0.7];
    else
        failRate = sum(~[mitm.intercepted]) / numel(mitm);
        if     failRate == 0,    col = [0 0.7 0];
        elseif failRate < 0.3,   col = [1 0.8 0];
        else,                    col = [0.9 0 0];
        end
    end

    rectangle( ...
        'Position', [pos(i,1)-nodeR  pos(i,2)-nodeR  2*nodeR  2*nodeR], ...
        'Curvature', [1 1], 'FaceColor', col, 'EdgeColor','k', 'LineWidth', 1.8);

    text(pos(i,1), pos(i,2), sprintf('M%d\n%.1f', i, pf.pv(i)), ...
         'HorizontalAlignment','center','VerticalAlignment','middle', ...
         'FontWeight','bold','FontSize', max(7, 10 - 0.3*plant.nMach));
end

%% Attacker glyph
triX = [0 -0.9 0.9] * 1.0;
triY = [-7 -8.5 -8.5];
patch(triX, triY, [0.9 0 0], 'EdgeColor','k','LineWidth', 1.5);
text(0, -9.4, 'MITM ATTACKER', 'HorizontalAlignment','center', ...
     'FontWeight','bold','FontSize', 11);

text(0, 9.4, 'Plant Layout', 'HorizontalAlignment','center', ...
     'FontWeight','bold','FontSize', 13);
hold off
end

%% ---------------- Force-directed layout (Fruchterman-Reingold) ----------------
function pos = forceDirectedLayout(A, span)
% Simple FR-style layout. Repulsion between all node pairs + attraction
% along edges, iterated to convergence. Final positions scaled to fit in
% a box of half-width `span`.

n = size(A, 1);
rng(7);                                     % deterministic layout
pos = (rand(n, 2) - 0.5) * 2;               % random init in [-1, 1]

iters = 200;
k     = sqrt(4 / max(n, 1));                % optimal distance constant
temp  = 0.1;                                % initial step size

for it = 1:iters
    disp = zeros(n, 2);

    % Repulsion (every pair pushes apart)
    for i = 1:n
        for j = 1:n
            if i == j, continue; end
            delta = pos(i, :) - pos(j, :);
            d = max(norm(delta), 1e-3);
            disp(i, :) = disp(i, :) + (delta / d) * (k^2 / d);
        end
    end

    % Attraction (edges pull together)
    for i = 1:n
        for j = i+1:n
            if A(i, j) == 0, continue; end
            delta = pos(i, :) - pos(j, :);
            d = max(norm(delta), 1e-3);
            attract = (d^2 / k);
            disp(i, :) = disp(i, :) - (delta / d) * attract;
            disp(j, :) = disp(j, :) + (delta / d) * attract;
        end
    end

    % Apply, capped by temperature; cool over time
    for i = 1:n
        d = max(norm(disp(i, :)), 1e-3);
        pos(i, :) = pos(i, :) + (disp(i, :) / d) * min(d, temp);
    end
    temp = max(temp * 0.97, 0.005);
end

% Centre and scale to fit the span
pos = pos - mean(pos, 1);
mx  = max(abs(pos(:)));
if mx > 0, pos = pos * (span / mx) * 0.85; end
end

%% ============================ Summary print ===========================
function printSummary(stats, attack_details, elapsed_runtime)
fprintf('\n=== SUMMARY ===\n');

n_intercepted = sum(strcmp({attack_details.status}, 'INTERCEPTED'));
n_successful  = sum(strcmp({attack_details.status}, 'SUCCESSFUL'));
n_clean       = sum(strcmp({attack_details.status}, 'CLEAN'));
n_tampered    = n_intercepted + n_successful;

fprintf('Total intercepted attempts: %d\n', stats.total);
fprintf('  Tampered (real attacks):  %d\n', n_tampered);
fprintf('    Intercepted by ECC:     %d\n', n_intercepted);
fprintf('    Slipped through:        %d\n', n_successful);
fprintf('  Clean (passive recon):    %d\n', n_clean);
fprintf('\n');

if n_tampered > 0
    fprintf('Detection rate (tampered only): %.2f%%\n', ...
            100 * n_intercepted / n_tampered);
end
fprintf('Overall prevention rate:        %.2f%%\n', ...
        100 * stats.prevented / stats.total);

if ~isempty(stats.interception_time)
    fprintf('Avg detection latency (sim):    %.1f ms\n', ...
            mean(stats.interception_time) * 1000);
end
fprintf('Simulation runtime:             %.3f seconds\n', elapsed_runtime);
end

%% ============================ ECC key management ======================
function [priv, pub] = genKeyPair(p)
priv = randi([2, p.n - 1]);
G    = [p.Gx, p.Gy];
pub  = scalar_mult(priv, G, p.a, p.p);
end

function secret = ECDH(priv, pub, p)
point = scalar_mult(priv, pub, p.a, p.p);
if isinf(point(1)), secret = 0; else, secret = point(1); end
end

%% ============================ ECC signature simulation ================
function sig = generateECCSignature(msg, secret)
% SIMPLIFIED hash-and-sign for demonstration. Real ECDSA computes
%   r = (k*G).x mod n
%   s = k^{-1}(z + r*d) mod n
% with k unique per signature (RFC 6979 deterministic-k recommended to
% avoid implementation flaws like the Sony PS3 incident).
sig = mod(sum(double(msg)) + secret, 997);
end

function ok = verifySignature(msg, sig, secret)
ok = (generateECCSignature(msg, secret) == sig);
end

function ok = checkMessageSignature(msg, signing_secret)
tok = regexp(msg, 'SIG:(\d+)', 'tokens');
if isempty(tok), ok = false; return; end
sig  = str2double(tok{1}{1});
core = regexprep(msg, '\|SIG:\d+', '');
ok   = verifySignature(core, sig, signing_secret);
end
