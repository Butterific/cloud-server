const SECURITY_HEADERS = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "interest-cohort=()",
};

const INDEX_HTML = `<!DOCTYPE html>
<html>
<head>
  <title>Cloud Data Server</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: "Helvetica Neue", Helvetica, sans-serif;
    }
    .label {
      font-size: 9.45pt;
      font-weight: bold;
      color: #575E75;
      white-space: pre;
    }
    .var {
      display: inline-block;
      background-color: #FF8C1A;
      border-radius: 15px;
      font-size: 8.1pt;
      color: white;
      font-weight: 500;
      padding-top: 7px;
      padding-bottom: 7px;
      padding-left: 8px;
      padding-right: 8px;
      text-decoration: none;
      white-space: pre;
    }
    .var.cloud::before {
      content: '☁ ';
    }
  </style>
</head>
<body>
  <h1 class="label">Cloud Data Server</h1>
  <a href="https://github.com/TurboWarp/cloud-server" class="var cloud">Source Code</a>
</body>
</html>
`;

const ROBOTS_TXT = "User-agent: *\nDisallow: /\n";

const CLOUD_PREFIXES = ["☁ ", ":cloud: "];
const VARIABLE_NAME_MAX_LENGTH = 1024;
const VALUE_MAX_LENGTH = 100000;
const USERNAME_MAX_LENGTH = 20;
const USERNAME_MIN_LENGTH = 1;
const USERNAME_REGEX = /^[a-z0-9_-]+$/i;
const GENERATED_USERNAME = /^player\d{2,7}$/i;

const FILTERS = `
^cosmosaura$
^themorningsun$
^LeopardFlash$
^RulerOfTheQueendom$
^originalwow$
^amylaser$
^deepThought01$
^achouse$
^mogibear$
^carpeediem$
^wheelsonfire$
^digitalgig$
^beezy333$
^caitspace$
^TheRiverClub$
^chrisg$
^cwillisf$
^ceebee$
^floralsunset$
^codubee$
^galbigrillmaster$
^technoboy10$
^spectrespecs$
^noncanonical$
^Ohsohpy$
^Harakou$
^BlueWillow78$
^deeplikethesea$
^NoodleKen11$
^ericr$
^scratchererik$
^cheddargirl$
^fcoCCT$
^pixelmoth$
^CallMeJMoney$
^GourdVibesOnly$
^MunchtheCat$
^Roxie916$
^justaspeckintheuni$
^lashaunan$
^lamatchalattei$
^shinyvase275$
^JumpingRabbits$
^ItzLinz$
^algorithmar$
^TheNuttyKnitter$
^paralellas$
^glowinday$
^dietbacon$
^Paddle2See$
^deism902$
^myuh$
^pamimus$
^ZipZapZuko$
^topball$
^rtrvmwe$
^binnieb$
^delasare$
^rosieatscratch$
^RupaLax$
^Rhyolyte$
^GardenSamantha$
^Onyx45$
^RagingAvocado$
^sgste735$
^LT7845$
^meyerhot$
^Johnny2By4$
^cardboardbee$
^pandatt$
^passiflora296$
^ninja11013$
^starrysky7$
^Purple4143$
^Zinnea$
^ScratchCat$
`;

const BLOCKED_USERNAME_PATTERNS = FILTERS.split("\n")
  .map((line) => line.trim())
  .filter((line) => line.length > 0)
  .map((line) => new RegExp(line, "i"));

const ERROR_CODE = 4000;
const USERNAME_CODE = 4002;
const OVERLOADED_CODE = 4003;
const SECURITY_CODE = 4005;

const ENABLE_RENAME = Deno.env.get("ENABLE_RENAME") === "true";
const ENABLE_DELETE = Deno.env.get("ENABLE_DELETE") === "true";
const TRUST_PROXY = Deno.env.get("TRUST_PROXY") === "true";
const ANONYMIZE_ADDRESSES = Deno.env.get("ANONYMIZE_ADDRESSES") === "true";
const ANONYMIZE_GENERATED_USERNAMES = Deno.env.get("ANONYMIZE_GENERATED_USERNAMES") !== "false";
const LOG_LEVEL = Deno.env.get("LOG_LEVEL") ?? "info";
const BUFFER_SENDS = Number.parseInt(Deno.env.get("BUFFER_SENDS") ?? "20", 10);
const MAX_ROOMS = Number.parseInt(Deno.env.get("MAX_ROOMS") ?? "16384", 10);
const JANITOR_INTERVAL_MS = Number.parseInt(Deno.env.get("JANITOR_INTERVAL_MS") ?? "60000", 10);
const JANITOR_THRESHOLD_MS = Number.parseInt(Deno.env.get("JANITOR_THRESHOLD_MS") ?? "3600000", 10);
const HANDSHAKE_TIMEOUT_MS = Number.parseInt(Deno.env.get("HANDSHAKE_TIMEOUT_MS") ?? "30000", 10);
const CLIENT_IDLE_TIMEOUT_MS = Number.parseInt(Deno.env.get("CLIENT_IDLE_TIMEOUT_MS") ?? "900000", 10);
const MAX_MESSAGE_CHARS = Number.parseInt(Deno.env.get("MAX_MESSAGE_CHARS") ?? "1000000", 10);

const debugEnabled = LOG_LEVEL === "debug";

function logInfo(message: string): void {
  console.info(message);
}

function logWarn(message: string): void {
  console.warn(message);
}

function logError(message: string): void {
  console.error(message);
}

function logDebug(message: string): void {
  if (debugEnabled) {
    console.debug(message);
  }
}

function getForwardedFor(req: Request): string | null {
  const value = req.headers.get("x-forwarded-for");
  if (!value) {
    return null;
  }
  return value.split(/\s*,\s*/)[0] || null;
}

function getAddress(req: Request): string {
  if (ANONYMIZE_ADDRESSES) {
    return "0.0.0.0";
  }
  if (TRUST_PROXY) {
    const forwarded = getForwardedFor(req);
    if (forwarded) {
      return forwarded;
    }
  }
  return req.headers.get("cf-connecting-ip") ?? "(remoteAddress missing)";
}

function isNaughty(text: string): boolean {
  const normalized = text.replace(/[^a-z0-9]/gi, "");
  for (const filter of BLOCKED_USERNAME_PATTERNS) {
    if (filter.test(normalized)) {
      return true;
    }
  }
  return false;
}

function parseUsername(username: string): string {
  if (ANONYMIZE_GENERATED_USERNAMES && GENERATED_USERNAME.test(username)) {
    return "player";
  }
  return username;
}

function isValidUsername(username: unknown): username is string {
  return typeof username === "string" &&
    username.length >= USERNAME_MIN_LENGTH &&
    username.length <= USERNAME_MAX_LENGTH &&
    USERNAME_REGEX.test(username) &&
    !isNaughty(username);
}

function isValidRoomID(id: unknown): id is string {
  return typeof id === "string" && id.length > 0 && id.length < 1000;
}

function isValidVariableName(name: unknown): name is string {
  if (typeof name !== "string") {
    return false;
  }
  if (name.length > VARIABLE_NAME_MAX_LENGTH) {
    return false;
  }
  for (const prefix of CLOUD_PREFIXES) {
    if (name === prefix) {
      return false;
    }
    if (name.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}

function isValidVariableValue(value: unknown): value is string | number {
  if (typeof value === "number") {
    return !Number.isNaN(value) &&
      Number.isFinite(value) &&
      value.toString().length <= VALUE_MAX_LENGTH;
  }
  if (typeof value !== "string") {
    return false;
  }
  if (value.length > VALUE_MAX_LENGTH) {
    return false;
  }
  if (value === "." || value === "-") {
    return false;
  }
  let seenDecimal = false;
  let index = 0;
  if (value.charCodeAt(0) === 45) {
    index++;
  }
  for (; index < value.length; index++) {
    const char = value.charCodeAt(index);
    if (char === 46) {
      if (seenDecimal) {
        return false;
      }
      seenDecimal = true;
    } else if (char < 48 || char > 57) {
      return false;
    }
  }
  return true;
}

function createSetMessage(name: string, value: string | number): string {
  return JSON.stringify({
    method: "set",
    name,
    value,
  });
}

class Room {
  readonly id: string;
  readonly variables: Map<string, string | number>;
  readonly clients: Client[];
  lastDisconnectTime = -1;
  readonly maxVariables = 128;
  readonly maxClients = 128;

  constructor(id: string) {
    this.id = id;
    this.variables = new Map();
    this.clients = [];
  }

  addClient(client: Client): void {
    if (this.clients.includes(client)) {
      throw new Error(`Client is already added to room ${this.id}`);
    }
    if (this.clients.length >= this.maxClients) {
      throw new Error(`Too many clients are connected to room ${this.id}`);
    }
    this.clients.push(client);
  }

  removeClient(client: Client): void {
    const index = this.clients.indexOf(client);
    if (index === -1) {
      throw new Error(`Client is not part of room ${this.id}`);
    }
    this.clients.splice(index, 1);
    this.lastDisconnectTime = Date.now();
  }

  getClients(): Client[] {
    return this.clients;
  }
}

class RoomList {
  readonly rooms = new Map<string, Room>();
  readonly maxRooms = MAX_ROOMS;

  has(id: string): boolean {
    return this.rooms.has(id);
  }

  get(id: string): Room {
    const room = this.rooms.get(id);
    if (!room) {
      throw new Error("Room does not exist");
    }
    return room;
  }

  create(id: string): Room {
    if (this.rooms.size >= this.maxRooms) {
      throw new ConnectionError(OVERLOADED_CODE, `Too many rooms to fit ${id}`);
    }
    if (this.has(id)) {
      throw new Error("Room already exists");
    }
    const room = new Room(id);
    this.rooms.set(id, room);
    logInfo(`Created room: ${id}`);
    return room;
  }

  remove(id: string): void {
    const room = this.get(id);
    if (room.getClients().length > 0) {
      throw new Error("Clients are connected to this room");
    }
    this.rooms.delete(id);
    logInfo(`Removed room: ${id}`);
  }

  janitor(): void {
    const removalThreshold = Date.now() - JANITOR_THRESHOLD_MS;
    const idsToRemove: string[] = [];
    for (const [id, room] of this.rooms.entries()) {
      if (room.getClients().length === 0 && room.lastDisconnectTime < removalThreshold) {
        idsToRemove.push(id);
      }
    }
    for (const id of idsToRemove) {
      this.remove(id);
    }
  }
}

class ConnectionError extends Error {
  readonly code: number;

  constructor(code: number, message: string) {
    super(`${message} (code ${code})`);
    this.code = code;
  }
}

class Client {
  ws: WebSocket | null;
  readonly ip: string;
  room: Room | null = null;
  username = "";
  readonly connectedAt = Date.now();
  lastMessageAt = Date.now();
  private logPrefix = "[]";

  constructor(ws: WebSocket, req: Request) {
    this.ws = ws;
    this.ip = getAddress(req);
    this.updateLogPrefix();
  }

  private updateLogPrefix(): void {
    this.logPrefix = `[${this.ip}`;
    if (this.username !== "") {
      this.logPrefix += ` "${this.username}"`;
    }
    if (this.room !== null) {
      this.logPrefix += ` in ${this.room.id}`;
    }
    this.logPrefix += "]";
  }

  log(message: string): void {
    logInfo(`${this.logPrefix} ${message}`);
  }

  error(message: string): void {
    logError(`${this.logPrefix} ${message}`);
  }

  send(data: string): void {
    if (this.ws === null) {
      this.log("Cannot send message; ws is null");
      return;
    }
    if (this.ws.readyState !== WebSocket.OPEN) {
      this.log(`Cannot send message; readyState ${this.ws.readyState}`);
      return;
    }
    this.ws.send(data);
  }

  close(code: number): void {
    if (this.ws !== null) {
      this.ws.close(code);
      this.ws = null;
    }
    if (this.room) {
      this.room.removeClient(this);
      this.room = null;
    }
  }

  setRoom(room: Room): void {
    if (this.room !== null) {
      throw new Error("Already joined a room");
    }
    room.addClient(this);
    this.room = room;
    this.updateLogPrefix();
  }

  setUsername(username: string): void {
    this.username = parseUsername(username);
    this.updateLogPrefix();
  }

  timedOut(reason: string): void {
    this.log(`Timed out: ${reason}`);
    this.close(ERROR_CODE);
  }
}

const rooms = new RoomList();
const clients = new Set<Client>();
const buffered = new Map<Client, string[]>();
const flushIntervalMs = BUFFER_SENDS > 0 ? Math.max(10, Math.floor(1000 / BUFFER_SENDS)) : 0;
let flushTimer: number | null = null;
let maintenanceTimer: number | null = null;

function addSecurityHeaders(headers: Headers): void {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(key, value);
  }
}

function sendToClient(client: Client, message: string): void {
  if (BUFFER_SENDS > 0) {
    const bucket = buffered.get(client);
    if (bucket) {
      bucket.push(message);
    } else {
      buffered.set(client, [message]);
    }
    scheduleFlush();
    return;
  }
  client.send(message);
}

function flushBuffered(): void {
  for (const [client, messages] of buffered.entries()) {
    if (messages.length > 0) {
      client.send(messages.join("\n"));
    }
  }
  buffered.clear();
}

function scheduleFlush(): void {
  if (BUFFER_SENDS <= 0 || flushTimer !== null || buffered.size === 0) {
    return;
  }
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushBuffered();
    if (buffered.size > 0) {
      scheduleFlush();
    }
  }, flushIntervalMs);
}

function runMaintenance(): void {
  rooms.janitor();
  const now = Date.now();
  for (const client of clients) {
    if (client.room === null && client.connectedAt < now - HANDSHAKE_TIMEOUT_MS) {
      client.timedOut("no handshake");
      continue;
    }
    if (client.lastMessageAt < now - CLIENT_IDLE_TIMEOUT_MS) {
      client.timedOut("idle");
    }
  }
}

function scheduleMaintenance(): void {
  if (maintenanceTimer !== null) {
    return;
  }
  if (clients.size === 0 && rooms.rooms.size === 0) {
    return;
  }
  maintenanceTimer = setTimeout(() => {
    maintenanceTimer = null;
    runMaintenance();
    scheduleMaintenance();
  }, JANITOR_INTERVAL_MS);
}

function isValidMessage(data: unknown): data is { method: string; [key: string]: unknown } {
  return !!data && typeof data === "object" && typeof (data as { method?: unknown }).method === "string";
}

function parseMessage(data: string): { method: string; [key: string]: unknown } {
  if (data.length > MAX_MESSAGE_CHARS) {
    throw new ConnectionError(ERROR_CODE, "Message too large");
  }
  const message: unknown = JSON.parse(data);
  if (!isValidMessage(message)) {
    throw new Error("Invalid message");
  }
  return message;
}

function serveHttp(req: Request): Response {
  const url = new URL(req.url);
  const headers = new Headers();
  addSecurityHeaders(headers);

  if (url.pathname === "/" || url.pathname === "/index.html") {
    headers.set("content-type", "text/html; charset=utf-8");
    return new Response(INDEX_HTML, { status: 200, headers });
  }
  if (url.pathname === "/robots.txt") {
    headers.set("content-type", "text/plain; charset=utf-8");
    return new Response(ROBOTS_TXT, { status: 200, headers });
  }
  headers.set("content-type", "text/plain; charset=utf-8");
  return new Response("Not Found", { status: 404, headers });
}

function handleWebSocket(req: Request): Response {
  const cookie = req.headers.get("cookie");
  const { socket, response } = Deno.upgradeWebSocket(req);
  const client = new Client(socket, req);
  clients.add(client);
  scheduleMaintenance();

  if (cookie?.startsWith("scratchsessionsid=")) {
    client.log("A connection closed for security reasons.");
    socket.onopen = () => {
      socket.send("The cloud data library you are using is putting your Scratch account at risk by sending us your login token for no reason. Change your Scratch password immediately, then contact the maintainers of that library for further information. This connection is being refused to protect your security.");
      socket.close(SECURITY_CODE);
    };
    return response;
  }

  function performHandshake(roomId: unknown, username: unknown): void {
    if (client.room) {
      throw new ConnectionError(ERROR_CODE, "Already performed handshake");
    }
    if (!isValidRoomID(roomId)) {
      const roomToLog = `${roomId}`.slice(0, 100);
      throw new ConnectionError(ERROR_CODE, `Invalid room ID: ${roomToLog}`);
    }
    if (!isValidUsername(username)) {
      const usernameToLog = `${username}`.slice(0, 100);
      throw new ConnectionError(USERNAME_CODE, `Invalid username: ${usernameToLog}`);
    }
    client.setUsername(username);
    if (rooms.has(roomId)) {
      const room = rooms.get(roomId);
      client.setRoom(room);
      const messages: string[] = [];
      for (const [name, value] of room.variables.entries()) {
        messages.push(createSetMessage(name, value));
      }
      if (messages.length > 0) {
        client.send(messages.join("\n"));
      }
    } else {
      client.setRoom(rooms.create(roomId));
    }
    client.log(`Joined room (peers: ${client.room.getClients().length})`);
  }

  function performDelete(variable: unknown): void {
    if (!ENABLE_DELETE) {
      return;
    }
    if (!client.room) {
      throw new ConnectionError(ERROR_CODE, "No room setup yet");
    }
    if (typeof variable !== "string") {
      throw new ConnectionError(ERROR_CODE, "Invalid variable name");
    }
    if (!client.room.variables.has(variable)) {
      throw new Error("Variable does not exist");
    }
    client.room.variables.delete(variable);
  }

  function performRename(oldName: unknown, newName: unknown): void {
    if (!ENABLE_RENAME) {
      return;
    }
    if (!client.room) {
      throw new ConnectionError(ERROR_CODE, "No room setup yet");
    }
    if (typeof oldName !== "string" || typeof newName !== "string") {
      throw new ConnectionError(ERROR_CODE, "Invalid variable name");
    }
    if (!isValidVariableName(newName)) {
      throw new Error(`Invalid variable name: ${newName}`);
    }
    const value = client.room.variables.get(oldName);
    if (typeof value === "undefined") {
      throw new Error("Variable does not exist");
    }
    client.room.variables.delete(oldName);
    client.room.variables.set(newName, value);
  }

  function performSet(variable: unknown, value: unknown): void {
    if (!client.room) {
      throw new ConnectionError(ERROR_CODE, "No room setup yet");
    }
    if (typeof variable !== "string") {
      throw new ConnectionError(ERROR_CODE, "Invalid variable name");
    }
    if (!isValidVariableValue(value)) {
      logDebug(`Ignoring invalid value: ${String(value)}`);
      return;
    }
    if (client.room.variables.has(variable)) {
      client.room.variables.set(variable, value);
    } else {
      if (client.room.variables.size >= client.room.maxVariables) {
        throw new Error("Too many variables");
      }
      client.room.variables.set(variable, value);
    }
    const roomClients = client.room.getClients();
    if (roomClients.length > 1) {
      const message = createSetMessage(variable, value);
      for (const otherClient of roomClients) {
        if (otherClient !== client) {
          sendToClient(otherClient, message);
        }
      }
    }
  }

  function processMessage(text: string): void {
    const message = parseMessage(text);
    switch (message.method) {
      case "handshake":
        performHandshake(message.project_id, message.user);
        break;
      case "set":
      case "create":
        performSet(message.name, message.value);
        break;
      case "delete":
        performDelete(message.name);
        break;
      case "rename":
        performRename(message.name, message.new_name);
        break;
      default:
        throw new ConnectionError(ERROR_CODE, `Unknown message method: ${message.method}`);
    }
  }

  socket.onopen = () => {
    client.log("Connection opened");
  };

  socket.onmessage = (event) => {
    if (socket.readyState !== WebSocket.OPEN) {
      return;
    }
    if (typeof event.data !== "string") {
      return;
    }
    client.lastMessageAt = Date.now();
    scheduleMaintenance();
    try {
      processMessage(event.data);
    } catch (error) {
      client.error(`Error handling connection: ${String(error)}`);
      if (error instanceof ConnectionError) {
        client.close(error.code);
      } else {
        client.close(ERROR_CODE);
      }
    }
  };

  socket.onerror = (event) => {
    client.error(`** ERROR ** ${String(event)}`);
    client.close(ERROR_CODE);
  };

  socket.onclose = (event) => {
    buffered.delete(client);
    clients.delete(client);
    client.ws = null;
    client.close(ERROR_CODE);
    client.log(`Connection closed: code ${event.code}`);
    scheduleMaintenance();
  };

  return response;
}

logInfo("Deno Deploy cloud server starting");
logInfo(`Naughty word detector has ${BLOCKED_USERNAME_PATTERNS.length} blocked phrases from 1 filters`);

Deno.serve((req) => {
  if (req.headers.get("upgrade")?.toLowerCase() === "websocket") {
    return handleWebSocket(req);
  }
  return serveHttp(req);
});
