declare namespace Express {
  export interface Request {
    user?: {
      sub: number;
      username: string;
    }
  }
}