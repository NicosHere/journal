import { DurableObject } from 'cloudflare:workers';
import worker, { JournalRoomCore } from './app.js';

export class JournalRoom extends DurableObject {
  async fetch(request) {
    return new JournalRoomCore(this.ctx.storage).fetch(request);
  }
}

export default worker;
