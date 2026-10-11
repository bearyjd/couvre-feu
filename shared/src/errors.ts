export class AppError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(status: number, code: string, message = code) {
        super(message);
        this.status = status;
        this.code = code;
    }
}
