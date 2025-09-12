namespace AspNetCoreIdentityApp.Core.Permission
{
    public static class Permission
    {
        public static class Stock
        {
            public const string View = "Permission.Stock.View";
            public const string Create = "Permission.Stock.Create";
            public const string Edit = "Permission.Stock.Edit";
            public const string Delete = "Permission.Stock.Delete";
        }
        public static class Order
        {
            public const string View = "Permission.Order.View";
            public const string Create = "Permission.Order.Create";
            public const string Edit = "Permission.Order.Edit";
            public const string Delete = "Permission.Order.Delete";
        }
        public static class Catalog
        {
            public const string View = "Permission.Catalog.View";
            public const string Create = "Permission.Catalog.Create";
            public const string Edit = "Permission.Catalog.Edit";
            public const string Delete = "Permission.Catalog.Delete";
        }
    }
}
