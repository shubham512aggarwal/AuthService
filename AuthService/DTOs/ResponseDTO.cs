namespace AuthService.DTOs
{
    public class ResponseDTO
    {
        public class ResultDTO
        {
            public bool Success { get; set; }
            public string Message { get; set; }
            public object Data { get; set; }
        }
    }
}
