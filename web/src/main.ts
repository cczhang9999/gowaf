import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import '@/assets/styles/index.css'
import * as ElementPlusIcons from '@element-plus/icons-vue'
import {
  Chart,
  LinearScale,
  CategoryScale,
  BarElement,
  LineElement,
  PointElement,
  ArcElement,
  Filler,
  Title,
  Tooltip,
  Legend
} from 'chart.js'

const app = createApp(App)

// Register Chart.js components globally.
// vue-chartjs registers the chart *controllers* (Line/Pie/Doughnut/...), but
// the elements and scales those controllers depend on must be registered here.
// ArcElement is required by Pie/Doughnut; Filler is required by fill: true.
Chart.register(
  LinearScale,
  CategoryScale,
  LineElement,
  PointElement,
  BarElement,
  ArcElement,
  Filler,
  Title,
  Tooltip,
  Legend
)

// Register all icons globally
Object.entries(ElementPlusIcons).forEach(([name, component]) => {
  app.component(name, component as any)
})

app.use(createPinia())
app.use(router)
app.use(ElementPlus)

app.mount('#app')